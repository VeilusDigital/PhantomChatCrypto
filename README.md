# PhantomChatCrypto
[![Swift Tests](https://github.com/VeilusDigital/PhantomChatCrypto/actions/workflows/swift.yml/badge.svg)](https://github.com/VeilusDigital/PhantomChatCrypto/actions/workflows/swift.yml)

The cryptographic core of **Phantom Chat** (Veilus Digital), extracted verbatim
from the iOS app so it can be **read, compiled, and run** by anyone — reviewers,
journalists, security researchers — without taking our word for anything.

> **Source-available for review.** You may read, build, and run this code to
> verify our claims. You may **not** reuse it in another product. See `LICENSE`.

The rest of the app and the backend remain closed-source; this package is the
part where the security actually lives.

## What's here

| File | What it is |
|---|---|
| `Sources/PhantomChatCrypto/Kyber768.swift` | ML-KEM-768 (FIPS 203) — post-quantum KEM, pure Swift |
| `Sources/PhantomChatCrypto/Keccak.swift` | Keccak-f[1600] + SHA3-256/512 + SHAKE128/256 (FIPS 202) |
| `Sources/PhantomChatCrypto/PQXDHHybrid.swift` | Hybrid combiner: classical X3DH secret + Kyber secret → root key |
| `Sources/PhantomChatCrypto/DoubleRatchet.swift` | Signal-protocol Double Ratchet (per-message keys, forward secrecy) |

These files are **byte-for-byte identical** to the app's `CryptoService.swift` /
`DoubleRatchet.swift` (only the `import` lines differ). The companion document
`phantom-chat-claim-audit.md` maps each marketing claim to these files.

## How to verify it yourself

```sh
swift test
```

That runs (all must pass):

- **FIPS 202 known-answer tests** — SHA3-256/512 and SHAKE128/256 against the
  published NIST reference values.
- **NTT correctness** — polynomial multiply checked against a schoolbook
  negacyclic convolution.
- **Reduction correctness** — Barrett reduction checked congruent across the
  entire `Int16` input range; canonical encoding verified.
- **ML-KEM-768 round-trips** — KeyGen → Encaps → Decaps agree; tampered
  ciphertext triggers implicit rejection.
- **Double Ratchet** — encrypt/decrypt round-trip.
- **PQXDH hybrid combiner** — deterministic and transcript-bound.
- **FIPS-203 conformance vs Apple CryptoKit** (`FIPSInteropTests`, requires
  macOS 26+): Phantom's Kyber and Apple's vetted `MLKEM768` exchange shared
  secrets **both directions**, and for the **same seed** Phantom's public key is
  **byte-identical** to Apple's. This is the strongest possible evidence that
  this is genuinely standard ML-KEM-768, not a look-alike.

## Honesty notes (the parts we want you to scrutinise)

- This is a **clean-room Swift implementation** of published standards (FIPS 202,
  FIPS 203, Signal Double Ratchet/X3DH), **not** libsignal or liboqs. The
  algorithms are standard; the implementation is ours.
- It has **not** had a paid third-party audit yet — that's on the roadmap. We're
  publishing it precisely so it can be reviewed.
- The interop tests use Apple's CryptoKit as the reference oracle; they need
  macOS 26 or later to run (older OSes will skip them).
- Found a problem? `support@veilusdigital.co`. We'd rather hear it from you.
