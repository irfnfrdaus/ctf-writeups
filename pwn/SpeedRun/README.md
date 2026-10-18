# SpeedRun

**Category:** Pwn
**Points:** 493
**Flag:** `nexsec26{Good___morning___or___perhaps___good___evening___everyone!!!}`
**Tools I used:** nasm, Python (pwn-style socket scripting), webhook.site, and DeepSeek: https://chat.deepseek.com/share/qfu9tvnq5jlzshhcax

> Please speedrun this chall.

The challenge hands you a static Linux binary behind `nc koala.nexsec.my <PORT>`, with `Dockerfile`, `chall`, `docker-compose`, and even `flag.txt` given to you up front. It doesn't matter that I could read the local `flag.txt` — the real flag only exists inside the remote container, under a randomised filename, and the binary is built to make getting it out as annoying as possible.

## TL;DR

The binary gates you behind three checks and then lets you run shellcode on an RWX page, but makes that shellcode nearly useless:

1. **Float equality against a random value from `/dev/urandom`**, compared with `comiss`. Sending `nan` makes the comparison "unordered," which sets the flags the same way an equal comparison would — so the check passes without me ever knowing the random value.
2. **Raw bit-pattern check on a second float** (`cmp` against `0x1337` on the *bits*, not the value). I needed an input that `scanf("%f", ...)` parses into exactly that 32-bit pattern. A hex float literal, `0x1.337p-137`, parses to an exact bit pattern with no rounding ambiguity — much safer than hunting for a decimal that happens to round correctly.
3. **Shellcode execution on an RWX page, but syscall bytes (`0f 05`) are banned from the input, stdin/stdout/stderr are closed before it runs, and a seccomp filter only allows `read write open close openat socket connect getdents64 exit`.**

For (3) I didn't need to smuggle the syscall opcode in at all — I shipped three `0x90` (NOP) placeholder bytes instead, and had the shellcode patch its own RWX page at runtime, overwriting those bytes with `0f 05 c3` (`syscall; ret`) right before using them. The scanner only ever sees NOPs.

With stdout gone, I couldn't just print the flag either. `socket` and `connect` were on the seccomp allow-list, so the shellcode opens its own outbound TCP connection and exfiltrates the flag that way — no local listener required.

## Step 1 — Beating the float equality check

The binary pulls a random `float` from `/dev/urandom`, reads my input with `scanf("%f", ...)`, and compares the two with `comiss`. I obviously can't guess a random 32-bit float. But `comiss`/`ucomiss` treat a comparison involving NaN as *unordered*, and on x86 that sets `ZF=1, PF=1, CF=1` — the exact same flags as a genuine equality. If the check that follows is just "jump if `ZF=1`," then feeding it `nan` makes it think the two values matched, regardless of what the random value actually was.

So the first line I send the binary is:

```
nan
```

(If the binary had used `ucomiss` and then checked for an *unmasked invalid-operation exception* instead of relying on the flags, this trick would need adjusting — but here it worked outright.)

## Step 2 — Hitting an exact bit pattern, not a value

The next check reads another float and compares its **raw 32 bits** against the constant `0x1337` — not the numeric value `0x1337` as a float, but the literal bit pattern `0x00001337`. That's a tiny positive subnormal number (exponent field all zero, mantissa `0x1337`), and subnormal spacing near zero is coarse enough that a decimal string can easily round to the wrong neighbouring bit pattern.

Rather than fight decimal rounding, I used a C99 hex float literal, which glibc's `scanf("%f", ...)` parses exactly:

```
0x1.337p-137
```

Since `0x1337 = 0x1.337 × 2^12`, and I need to land on `0x1337 × 2^-149` (the value of mantissa `0x1337` at the smallest subnormal exponent), the exponent works out to `12 - 149 = -137`. This parses to the exact target bits with zero rounding risk, which a long decimal approximation can't guarantee.

## Step 3 — Getting a syscall past a byte filter

The binary now accepts a 2-byte little-endian length, then that many bytes of shellcode, and drops them onto an RWX page. Before running them it:

- Scans the submitted bytes and kills me if it finds `0f 05` (the `syscall` opcode) anywhere.
- Closes stdin, stdout, and stderr.
- Installs a seccomp filter that only allows `read`, `write`, `open`, `close`, `openat`, `socket`, `connect`, `getdents64`, `exit`.

The byte scan only ever looks at what I *submit* — it doesn't re-scan the RWX page after execution starts. So instead of shipping `0f 05` anywhere in my shellcode, I shipped three placeholder `0x90` (NOP) bytes at a known offset, and had my own shellcode overwrite them at runtime with `0f 05 c3` (`syscall; ret`) before ever calling into them. Every syscall in the rest of the shellcode goes through a `call` to that patched stub rather than an inline `syscall` instruction, so the forbidden byte pair never appears in what gets scanned.

I first considered jumping to a hand-built gadget on the stack, but `GNU_STACK` was RW-only (NX stack) — anything executable had to live in the already-RWX mmap'd page the binary gave me, so the stub had to be part of my own shellcode, not stack data.

## Step 4 — Finding a flag with a randomised name, with no stdout

The flag file isn't called `flag.txt` on the remote box — it's renamed to something like `flag-<random-hex>.txt`, and I have no way to `ls` it since stdout/stderr are dead. `getdents64` was on the seccomp allow-list for exactly this reason: the shellcode opens the current directory, reads its entries, and walks the `linux_dirent64` records looking for a name whose first four bytes match `"flag"`. Once found, it opens that file by the name it just read out of the directory listing and reads its contents into a buffer.

## Step 5 — Getting the flag out without a public IP

This is where my setup became the real obstacle, not the binary. I was on a locked-down work laptop: no public IP for a reverse shell, `ngrok` wanted a card I didn't want to hand over, and `serveo` kept getting blocked. `write(1, ...)` was useless anyway since stdout was closed. But `socket` and `connect` were both on the seccomp allow-list, which meant the shellcode could dial *out* on its own — it didn't need me to host anything.

So instead of a reverse shell, the shellcode:

1. Opens a TCP socket and `connect()`s straight to `webhook.site` on port 80 (plain HTTP — doing TLS by hand in shellcode for an HTTPS endpoint wasn't worth it).
2. Builds a raw HTTP `GET` request with the flag contents placed in the request path/query string, and a `Host: webhook.site` header.
3. Sends it with `write(sockfd, ...)` over the socket it just opened — using the socket fd instead of the closed stdout fd.

Then I just opened my unique `webhook.site` URL in a normal browser tab and read the incoming request log. The flag showed up in the captured request's path, with spaces rendered as underscores in the display (the actual flag uses spaces).

## Step 6 — The exploit script

With the shellcode assembled (`nasm -f bin sc.asm -o sc.bin`, double-checked with `xxd -p` that no `0f 05` sequence appears anywhere in the output), the Python side of the exploit was simple TCP scripting against `koala.nexsec.my`:

1. Connect over TCP to the challenge host and port.
2. Send `nan\n` to clear the first check.
3. Send `0x1.337p-137\n` to clear the second check.
4. Send a 2-byte little-endian length of the shellcode, followed by the raw shellcode bytes.
5. Wait a moment, then check the `webhook.site` dashboard in the browser for the exfiltrated request.

## The flag

```
nexsec26{Good___morning___or___perhaps___good___evening___everyone!!!}
```

The flag text (once the underscores are read back as the spaces `webhook.site`'s display mangled) is a cheeky nod to not knowing — or caring — what time zone the person on the other end of a CTF challenge is in.

## Mitigations

- **Float equality on attacker-controlled randomness:** don't rely on bitwise/instruction-level equality checks against external input without also rejecting non-finite values (`NaN`, `±Inf`) explicitly before comparing.
- **Bit-pattern comparisons from `scanf`-parsed floats:** if you intend a value check, compare the parsed value, not the raw bits — or validate the input class (reject subnormals/NaN/Inf) before trusting the bit pattern.
- **Byte-level shellcode scanning:** a static byte scan over submitted shellcode is trivially defeated by self-modifying code; RWX pages let the scanned bytes and the executed bytes diverge. Don't allow writable+executable memory for untrusted payloads, and don't treat a byte-signature scan as a security boundary.
- **Seccomp allow-lists:** `socket`/`connect` in the allow-list, combined with closing all standard file descriptors, still leaves a wide-open exfiltration channel. If the intent is to block all outbound communication, `socket`/`connect` need to come off the list too, or be scoped with a stricter seccomp filter (e.g. `seccomp-bpf` argument filtering on the address family).

## The exploit chain, at a glance

```
NaN bypasses comiss equality check (unordered == flags-equal)
   -> exact hex float literal (0x1.337p-137) hits the exact raw-bit target
   -> self-patching NOP->syscall stub smuggles syscalls past a byte scanner
   -> getdents64 finds the randomly-named flag file with stdout closed
   -> socket+connect exfiltrate the flag via an outbound HTTP request to
      webhook.site, read in a plain browser tab with no listener needed
```
