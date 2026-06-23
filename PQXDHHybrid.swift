// Extracted verbatim from Phantom Chat (Veilus Digital) for public review.
// Source-available — see LICENSE. Cryptographic logic is unmodified;
// only imports differ from the in-app file.

import Foundation
import CryptoKit

// ═══════════════════════════════════════════════════════════════════════
// MARK: - PQXDH Hybrid Combiner
// ═══════════════════════════════════════════════════════════════════════
//
// Takes a classical X3DH shared secret + a Kyber-768 shared secret +
// a transcript hash (over both peers' public keys + ciphertext) and
// derives a 64-byte hybrid root via HKDF-SHA256. If EITHER component is
// secure (classical OR post-quantum), the result is. Domain-separated
// from the legacy classical path so old sessions don't collide.

// `nonisolated` — same reasoning as Kyber768: pure stateless combiner
// math, called from the X3DHProtocol actor and from background-key
// recovery paths. Project-wide default MainActor isolation would force
// every caller to hop, which is both unnecessary and warning noise.
nonisolated enum PQXDHHybrid {

    static let domain = "phantom-pqxdh-v1"

    /// Combine an existing 32-byte classical X3DH shared secret with a
    /// Kyber-768 shared secret and a transcript hash. Output is 64 bytes
    /// (32 root + 32 chain seed) — caller can split as needed.
    static func combine(classicalSS: Data, pqSS: Data, transcriptHash: Data) -> Data {
        let ikm = classicalSS + pqSS
        var salt = transcriptHash
        salt.append(contentsOf: Array(domain.utf8))
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: Data("phantom-pqxdh-root".utf8),
            outputByteCount: 64
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    /// Hash a transcript: H(idA || idB || pqPub || pqCt). Used by both
    /// sides to bind the hybrid root to the exact key exchange.
    static func transcript(initiatorIdentity: Data,
                           responderIdentity: Data,
                           kyberPub: Data,
                           kyberCiphertext: Data) -> Data {
        var input = Data()
        input.append(initiatorIdentity)
        input.append(responderIdentity)
        input.append(kyberPub)
        input.append(kyberCiphertext)
        let h = PCKeccak.sha3_256(Array(input))
        return Data(h)
    }
}
