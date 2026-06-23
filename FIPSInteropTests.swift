import XCTest
import CryptoKit
@testable import PhantomChatCrypto

/// Gold-standard FIPS-203 conformance check: interoperate with Apple
/// CryptoKit's vetted `MLKEM768`. If Phantom's hand-written Kyber-768 can
/// exchange shared secrets bit-for-bit with Apple's implementation in both
/// directions, it IS standard ML-KEM-768 — no external KAT files required.
final class FIPSInteropTests: XCTestCase {

    // Phantom encapsulates to an Apple public key; Apple must decapsulate to
    // the identical shared secret.
    func testPhantomEncaps_AppleDecaps() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { throw XCTSkip("ML-KEM requires OS 26+") }
        let appleSK = try MLKEM768.PrivateKey()
        let applePK = appleSK.publicKey.rawRepresentation
        XCTAssertEqual(applePK.count, Kyber768.pubKeyBytes)

        let (ct, ssPhantom) = Kyber768.encaps(publicKey: Array(applePK))
        let ssApple = try appleSK.decapsulate(Data(ct))
        XCTAssertEqual(ssPhantom, Array(ssApple.withUnsafeBytes { Data($0) }),
                       "Apple must recover the same shared secret from Phantom's ciphertext")
    }

    // Apple encapsulates to a Phantom public key; Phantom must decapsulate to
    // the identical shared secret.
    func testAppleEncaps_PhantomDecaps() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { throw XCTSkip("ML-KEM requires OS 26+") }
        let (pkP, skP) = Kyber768.keyGen()
        let applePK = try MLKEM768.PublicKey(rawRepresentation: Data(pkP))
        let result = try applePK.encapsulate()
        let ssPhantom = Kyber768.decaps(secretKey: skP, ciphertext: Array(result.encapsulated))
        XCTAssertEqual(ssPhantom, Array(result.sharedSecret.withUnsafeBytes { Data($0) }),
                       "Phantom must recover the same shared secret from Apple's ciphertext")
    }

    // Deterministic keygen KAT: same seed (d||z) must yield the same public key
    // as Apple, proving byte-exact FIPS-203 KeyGen.
    func testKeyGenSeedMatchesApple() throws {
        guard #available(macOS 26.0, iOS 26.0, *) else { throw XCTSkip("ML-KEM requires OS 26+") }
        var d = [UInt8](repeating: 0, count: 32)
        var z = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { d[i] = UInt8(i); z[i] = UInt8(255 - i) }

        // Phantom keygen with injected (d, z).
        var calls = 0
        let (pkP, _) = Kyber768.keyGen(randomBytes: { defer { calls += 1 }; return calls == 0 ? d : z })

        // Apple keygen from the same seed d||z.
        let appleSK = try MLKEM768.PrivateKey(seedRepresentation: Data(d + z), publicKey: nil)
        XCTAssertEqual(Array(appleSK.publicKey.rawRepresentation), pkP,
                       "Phantom's KeyGen public key must match Apple's for the same seed")
    }
}
