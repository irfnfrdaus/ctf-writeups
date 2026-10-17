# Very Fest — NexSec 2026 (Misc)

**Category:** Misc
**Flag:** `nexsec26{decentralization_means_giving_up_dominance_over_security}`
**Solved with DeepSeek** — chat pasted below in full.

## TL;DR

The challenge handed me a single `.evm` file and a description pointing at
`re.hanz.dev` ("Bytecode analysis made easy"). The `.evm` was raw EVM
(Ethereum Virtual Machine) bytecode as a hex string. I didn't need a
decompiler at all — the flag was sitting in the bytecode as plaintext
`PUSH32`/`PUSH2` constants that the contract uses to validate an input
string. Scanning the hex for ASCII and stitching the three chunks back
together gave me the flag directly.

## The challenge

> Very Fest
> Bytecode analysis made easy (re.hanz.dev)
> Flag format: `nexsec26{.............}`

The challenge page also showed `nexsec26{4b8d2f1a6c0e7d9b3a5f8c2e1d0a99b9}`,
which I took as a format example / decoy — it isn't the real flag.

The only attachment was `VeryFest.evm`, containing this hex blob:

```
36600490106034575f3560e01c63146e61ed8114602e5763799320bb811460435763d99a8dc381146052576034565b34156038575b5f5ffd5b5f5460c052602060c0f35b34603457600154151561024956fe5b503460345736600490036020901260345736600435600419811160345760040181811160345780820360201160345780356020820182811061026657808403931061026657918211603457603f198211603457603f8201601f191660405161013f811160bd57506101405b602082036020909210610266575b9081015f905282602001909182375f546001810190811061026657805f559060200160c0528160e0525f610100528161012052906042148015610192575060c05f610115916101d6565b7f6e657873656332367b646563656e7472616c697a6174696f6e5f6d65616e735f14156101905760c06020610149916101d6565b7f676976696e675f75705f646f6d696e616e63655f6f7665725f7365637572697414156101905760c0604061017d916101d6565b61797d60f01b1415610190576001610192565b5f5b80156101cd5760018055339160a052907f6747c18256028de8cd2fa276e75d6b4193ac34c1b55fa8e71797ac132d32ad39602060a0a26101d0565b90505b61024956fe5b606081015160408201519151818410156102285783830192831061026657909101518282039290911061026657602082101561021f579060200360031b90811c901b5f90610232565b90505f90610232565b50505050600160a0515b5f82146102425760018214610247575b905090565bfe5b156102595760016101405261025f565b5f610140525b6020610140f35b634e487b7160e01b5f52601160045260245ffd
```

## 1. Recognizing the format

The `60`/`63`/`5b` byte patterns right at the start (`PUSH1`, `PUSH4`,
`JUMPDEST`) were the giveaway that this is compiled EVM bytecode, not just
arbitrary binary data — the "bytecode analysis" hint in the challenge
description confirmed it. Rather than reach for a full decompiler, I asked
DeepSeek to help me get oriented on reading it.

## 2. Spotting the ASCII hiding in the constants

EVM bytecode stores string/byte literals as big operands to `PUSHn`
opcodes (`0x7f` = `PUSH32`, `0x61` = `PUSH2`, etc.), immediately followed by
the raw bytes. Scanning the hex for long runs that decode to printable
ASCII turned up three chunks, each preceded by its `PUSHn` opcode:

| Opcode | Hex operand | Decoded ASCII |
|---|---|---|
| `PUSH32` (`7f`) | `6e657873656332367b646563656e7472616c697a6174696f6e5f6d65616e735f` | `nexsec26{decentralization_means_` |
| `PUSH32` (`7f`) | `676976696e675f75705f646f6d696e616e63655f6f7665725f73656375726974` | `giving_up_dominance_over_securit` |
| `PUSH2` (`61`) | `797d` | `y}` |

One thing I double-checked: DeepSeek decoded the last chunk as `ay}`, but
that leading `61` is the `PUSH2` opcode itself, not data — the operand is
just `797d` = `y}`. The `60f01b` after it (`PUSH1 0xf0`, `SHL`) shifts those
two bytes to the top of the word so they can be compared against the last
two bytes of the input.

Concatenating the three pieces in order (32 + 32 + 2 = 66 bytes, matching
the contract's own length check further up in the bytecode) reconstructs
the flag directly:

```
nexsec26{decentralization_means_giving_up_dominance_over_security}
```

## 3. What the contract actually does (for completeness)

I didn't need this to get the flag, but reading a bit further confirms the
story: the contract takes a `bytes` input, requires it to be exactly `0x42`
(66) bytes, and does three `EQ` comparisons (`14` opcode) between slices of
the input and the three constants above. If every comparison passes, it
sets a storage flag and emits an event — i.e. the "flag" string is also
the expected *preimage* the contract is checking submissions against. For
this challenge, though, the constants themselves were the deliverable.

## Flag

```
nexsec26{decentralization_means_giving_up_dominance_over_security}
```

## Mitigations (if this were a real contract)

- **Never store secrets or validation targets as plaintext bytecode
  constants.** Anything pushed onto the stack as a literal is trivially
  recovered by anyone who can read the deployed bytecode — there is no
  "server side" to keep it on in a smart contract.
- If a commit/reveal or password-style check is genuinely needed on-chain,
  compare against a **hash** of the secret (e.g. `keccak256`), not the
  secret itself, and have the caller supply the preimage to be hashed and
  compared — never embed the preimage in the contract.
- Treat all deployed bytecode as public: this is actually *expected*
  behavior for a public blockchain, so the real lesson is architectural —
  decide up front what must stay off-chain if it needs to stay secret.

## Exploit chain at a glance

```
.evm file (hex)
      │
      ▼
recognize EVM opcodes (60/63/5b/7f...)
      │
      ▼
scan PUSH32 / PUSH2 operands for printable ASCII
      │
      ├── chunk 1: "nexsec26{decentralization_means_"
      ├── chunk 2: "giving_up_dominance_over_securit"
      └── chunk 3: "y}"
      │
      ▼
concatenate in bytecode order
      │
      ▼
nexsec26{decentralization_means_giving_up_dominance_over_security}
```

## Full DeepSeek chat

> i got a ctf challenge in misc category, its called "Very Fest". the only
> thing they gave me is a .evm file and the description says "Bytecode
> analysis made easy (re.hanz.dev)". flag format is nexsec26{.............}
>
> the file content is this hex, i think its some ethereum bytecode? not
> really sure how to read it
>
> 36600490106034575f3560e01c63146e61ed8114602e5763799320bb811460435763d99a8dc381146052576034565b34156038575b5f5ffd5b5f5460c052602060c0f35b34603457600154151561024956fe5b503460345736600490036020901260345736600435600419811160345760040181811160345780820360201160345780356020820182811061026657808403931061026657918211603457603f198211603457603f8201601f191660405161013f811160bd57506101405b602082036020909210610266575b9081015f905282602001909182375f546001810190811061026657805f559060200160c0528160e0525f610100528161012052906042148015610192575060c05f610115916101d6565b7f6e657873656332367b646563656e7472616c697a6174696f6e5f6d65616e735f14156101905760c06020610149916101d6565b7f676976696e675f75705f646f6d696e616e63655f6f7665725f7365637572697414156101905760c0604061017d916101d6565b61797d60f01b1415610190576001610192565b5f5b80156101cd5760018055339160a052907f6747c18256028de8cd2fa276e75d6b4193ac34c1b55fa8e71797ac132d32ad39602060a0a26101d0565b90505b61024956fe5b606081015160408201519151818410156102285783830192831061026657909101518282039290911061026657602082101561021f579060200360031b90811c901b5f90610232565b90505f90610232565b50505050600160a0515b5f82146102425760018214610247575b905090565bfe5b156102595760016101405261025f565b5f610140525b6020610140f35b634e487b7160e01b5f52601160045260245ffd
>
> can u help me figure out what this contract does and how to get the flag?
> where do i even start

**DeepSeek:**
> You're right to suspect it's EVM bytecode—the `60`/`63` prefixes and
> `PUSH` patterns are classic Ethereum Virtual Machine opcodes. But for
> this CTF, you likely don't need to fully "read" the bytecode. The flag
> pieces are often hidden as plaintext constants, and I can already see
> readable fragments in your hex.
>
> **What's hiding in the bytecode**
>
> Looking closely at the middle of your hex string, there are clear ASCII
> fragments encoded as `PUSH` arguments:
>
> - `6e657873656332367b646563656e7472616c697a6174696f6e5f6d65616e735f` →
>   `nexsec26{decentralization_means_`
> - `676976696e675f75705f646f6d696e616e63655f6f7665725f73656375726974` →
>   `giving_up_dominance_over_securit`
> - `61797d` → `ay}`
>
> Putting it together:
> `nexsec26{decentralization_means_giving_up_dominance_over_security}`
>
> The contract logic likely checks these exact strings against some
> inputs, but the flag itself is just sitting there in the code.
>
> **How you can verify it yourself**
>
> 1. Use an online decompiler — paste the hex into ethervm.io or a
>    bytecode decompiler to get readable pseudo-code.
> 2. Disassemble to opcodes with a hex-to-opcode converter to see the raw
>    `PUSH` instructions.
> 3. Look for `PUSH` constants — `63` is `PUSH4`, `64` is `PUSH5`, etc.
>    Those fragments are loaded onto the stack, likely to compare against
>    your input (the flag format check).
>
> Since this is a misc challenge, the intended path is probably exactly
> what you just did: recognize the hex, scan for ASCII, and reconstruct
> the flag.

> got the flag, thank you

**DeepSeek:**
> You're welcome! Quick note for next time you hit a similar misc/EVM
> challenge: the giveaway was those long `PUSH` sequences in the middle of
> the bytecode — any time you see `6e6578...` (`nex...`) or similar, it's
> worth hex-decoding chunks by hand or with `xxd -r -p`. The contract logic
> (the `14` = `EQ` comparisons, the `61...` jumps) was just validating
> those pieces, but the flag was sitting in plain sight as `PUSH`
> constants.
