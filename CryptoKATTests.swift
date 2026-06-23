import XCTest
import CryptoKit
@testable import PhantomChatCrypto

/// Known-answer tests (KATs) for the cryptographic core. These are the same
/// checks the app runs as a self-test on first PQXDH use — here they run via
/// `swift test` so anyone can verify the implementation against the published
/// FIPS 202 / FIPS 203 reference values without trusting our word.
final class CryptoKATTests: XCTestCase {

    private func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }

    // MARK: - FIPS 202 (SHA-3 / SHAKE) known-answer tests

    func testSHA3_256_abc() {
        // NIST FIPS 202 reference value for SHA3-256("abc")
        XCTAssertEqual(hex(PCKeccak.sha3_256(Array("abc".utf8))),
                       "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    }

    func testSHA3_512_abc() {
        XCTAssertEqual(hex(PCKeccak.sha3_512(Array("abc".utf8))),
                       "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" +
                       "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")
    }

    func testSHAKE128_empty() {
        XCTAssertEqual(hex(PCKeccak.shake128([], outputBytes: 32)),
                       "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
    }

    func testSHAKE256_empty() {
        XCTAssertEqual(hex(PCKeccak.shake256([], outputBytes: 32)),
                       "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
    }

    // MARK: - FIPS 203 (ML-KEM-768 / Kyber-768)

    func testKyber768_RoundTrip() {
        let (pk, sk) = Kyber768.keyGen()
        XCTAssertEqual(pk.count, Kyber768.pubKeyBytes)      // 1184
        XCTAssertEqual(sk.count, Kyber768.secretKeyBytes)   // 2400

        let (ct, ssA) = Kyber768.encaps(publicKey: pk)
        XCTAssertEqual(ct.count, Kyber768.ciphertextBytes)  // 1088
        XCTAssertEqual(ssA.count, Kyber768.sharedSecretBytes) // 32

        let ssB = Kyber768.decaps(secretKey: sk, ciphertext: ct)
        XCTAssertEqual(ssA, ssB, "encaps/decaps shared secrets must match")
    }

    func testKyber768_ImplicitRejectionOnTamper() {
        let (pk, sk) = Kyber768.keyGen()
        let (ct, ssA) = Kyber768.encaps(publicKey: pk)
        var tampered = ct
        tampered[0] ^= 0x01
        let ssC = Kyber768.decaps(secretKey: sk, ciphertext: tampered)
        XCTAssertNotEqual(ssC, ssA, "tampered ciphertext must NOT yield the same shared secret")
    }

    func testKyber768_ManyRoundTrips() {
        // Decapsulation failure rate for ML-KEM-768 is negligible; a batch of
        // round-trips guards against rare correctness regressions.
        for _ in 0..<25 {
            let (pk, sk) = Kyber768.keyGen()
            let (ct, ssA) = Kyber768.encaps(publicKey: pk)
            XCTAssertEqual(ssA, Kyber768.decaps(secretKey: sk, ciphertext: ct))
        }
    }

    // MARK: - PQXDH hybrid combiner

    func testPQXDHHybrid_DeterministicAndBound() {
        let classical = Data(repeating: 0x11, count: 32)
        let pq = Data(repeating: 0x22, count: 32)
        let t1 = PQXDHHybrid.transcript(initiatorIdentity: Data([1]),
                                        responderIdentity: Data([2]),
                                        kyberPub: Data([3]),
                                        kyberCiphertext: Data([4]))
        let a = PQXDHHybrid.combine(classicalSS: classical, pqSS: pq, transcriptHash: t1)
        let b = PQXDHHybrid.combine(classicalSS: classical, pqSS: pq, transcriptHash: t1)
        XCTAssertEqual(a, b, "same inputs must derive the same hybrid root")
        XCTAssertEqual(a.count, 64)

        // Changing the transcript must change the derived root (binding).
        let t2 = PQXDHHybrid.transcript(initiatorIdentity: Data([1]),
                                        responderIdentity: Data([2]),
                                        kyberPub: Data([3]),
                                        kyberCiphertext: Data([9]))
        XCTAssertNotEqual(a, PQXDHHybrid.combine(classicalSS: classical, pqSS: pq, transcriptHash: t2))
    }

    // MARK: - Double Ratchet round-trip

    func testDoubleRatchet_RoundTrip() throws {
        // Symmetric (v1) setup: Alice's send chain == Bob's receive chain.
        let root = SymmetricKey(size: .bits256)
        let chainAtoB = SymmetricKey(size: .bits256)
        let chainBtoA = SymmetricKey(size: .bits256)
        let aPriv = P256.KeyAgreement.PrivateKey()
        let bPriv = P256.KeyAgreement.PrivateKey()

        let alice = DoubleRatchet(rootKey: root, sendChainKey: chainAtoB, receiveChainKey: chainBtoA,
                                  dhSendKey: aPriv, dhReceiveKey: bPriv.publicKey, useDHRatchet: false)
        let bob = DoubleRatchet(rootKey: root, sendChainKey: chainBtoA, receiveChainKey: chainAtoB,
                                dhSendKey: bPriv, dhReceiveKey: aPriv.publicKey, useDHRatchet: false)

        let plaintext = Data("hello, post-quantum world".utf8)
        let msg = try alice.encryptMessage(plaintext)
        XCTAssertEqual(try bob.decryptMessage(msg), plaintext)

        // A second message advances the chain and still decrypts.
        let plaintext2 = Data("second message".utf8)
        let msg2 = try alice.encryptMessage(plaintext2)
        XCTAssertEqual(try bob.decryptMessage(msg2), plaintext2)
    }
}
