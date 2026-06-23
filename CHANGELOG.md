# Changelog — PhantomChatCrypto

This log records changes to the cryptographic core that ships in Phantom Chat.
It's deliberately candid: if we fixed something, it's written down here, with
how it was found and how the fix was verified. (For the marketing-claim-to-code
map, see `phantom-chat-claim-audit.md`.)

## 2026-06-24 — ML-KEM-768 made correct and FIPS-203-conformant

**Context.** When the cryptographic core was extracted into this standalone,
testable package, the test suite immediately caught that the hand-written
ML-KEM-768 (Kyber-768) post-quantum KEM **did not round-trip** — encapsulation
and decapsulation produced different shared secrets every time. The app's
built-in self-test had been logging this failure, but only to a log file, so it
had gone unnoticed. **The post-quantum layer was not functioning. It is now,
and it is validated against Apple CryptoKit's vetted `MLKEM768`.**

Three real bugs were found and fixed (all in `Kyber768.swift`; the same fixes
are in the app's `CryptoService.swift`):

1. **Extra Montgomery factor on the encryption vector `u`.**
   `kPkeEncrypt` built `u` with `matrixPolyVecMul`, which applies `polyToMont`.
   The immediately-following inverse-NTT (`invntt_tomont`) already performs the
   single Montgomery conversion, so this was a *second* factor that the public
   key `t` does not carry. The asymmetry meant `v − s∘u` never cancelled and
   decapsulation always diverged. Fixed: compute `u` via a plain
   basemul-accumulate (no `tomont`), then inverse-NTT.

2. **Secret vector `s` serialized without reduction.**
   `kPkeKeyGen` wrote `s` to bytes straight after the NTT, whose output is not
   in `[0,q)`; the 12-bit packing then corrupted the secret key on read-back.
   Fixed by canonicalising before serialising (see #3).

3. **Non-canonical public/secret key encoding.**
   `polyToBytes` (12-bit packing) requires coefficients in `[0,q)`, but
   `barrettReduce` is only *congruent* mod q — it can return `q` itself —
   producing bytes that differed from FIPS-203 for the same seed. Fixed by
   canonicalising `t` and `s` with `polyFreeze` (`conditionalSubQ ∘
   barrettReduce`) before serialising.

**How it was verified.**
- All low-level primitives checked independently: FIPS-202 SHA3/SHAKE
  known-answer tests; NTT multiply vs schoolbook negacyclic convolution;
  Barrett reduction congruent across the entire `Int16` range; canonical
  encoding round-trips.
- ML-KEM-768 KeyGen → Encaps → Decaps round-trips (single and batched);
  tampered ciphertext triggers implicit rejection.
- **Conformance vs Apple CryptoKit `MLKEM768`** (`FIPSInteropTests`): shared
  secrets match in *both* directions (Phantom↔Apple), and for the same seed
  `d‖z` Phantom's public key is **byte-identical** to Apple's. This is the
  gold-standard evidence that this is genuinely standard ML-KEM-768.
- Confirmed end-to-end in the live app: a fresh two-device conversation
  establishes and messages decrypt correctly.

Run `swift test` to reproduce all of the above (15 tests).

**Note for reviewers.** `barrettReduce` omits the `+(1<<25)` rounding term used
by pq-crystals; we verified it is congruent for all `Int16` inputs and that
`polyFreeze` canonicalises before any serialisation, so output is exact. We'd
still welcome scrutiny here.

## Earlier

- Initial extraction of the crypto core (Keccak/FIPS-202, Kyber-768/FIPS-203,
  PQXDH hybrid combiner, Double Ratchet) verbatim from the app for public
  review.

---

### Related app-level changes (context only — not part of this crypto package)

These shipped in the same app build but live outside this package, so they're
listed only for context (the app remains closed-source):

- Photos/videos stripped of EXIF/GPS metadata before encryption + upload.
- Disappearing messages auto-deleted server-side (Firestore TTL).
- Safety-number verification kept on-device (no server-side audit trail).
- File attachments (audio/PDF/docs) sent E2E; inline audio playback.
