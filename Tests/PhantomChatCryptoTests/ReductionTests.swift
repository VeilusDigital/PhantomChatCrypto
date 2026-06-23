import XCTest
@testable import PhantomChatCrypto

/// Verifies the modular-reduction helpers are exact across their whole input
/// domain — a correctness prerequisite for FIPS-203 conformance.
final class ReductionTests: XCTestCase {
    typealias K = Kyber768

    // barrettReduce must be congruent to a (mod q) for EVERY Int16 input.
    func testBarrettReduceCongruentAllInt16() {
        var bad = 0, first = 0
        for a in Int(Int16.min)...Int(Int16.max) {
            let r = Int(K.barrettReduce(Int16(a)))
            // congruent mod q?
            if ((r - a) % K.q) != 0 { if bad == 0 { first = a }; bad += 1 }
        }
        print("DIAG barrett not-congruent count: \(bad) (first bad input \(first))")
        XCTAssertEqual(bad, 0)
    }

    // polyFreeze output must be the canonical residue in [0, q).
    func testFreezeCanonical() {
        var p = K.Poly()
        var v = Int16.min
        for i in 0..<K.n { p.coeffs[i] = v; v = v &+ 257 }
        var f = p; K.polyFreeze(&f)
        var outOfRange = 0, notCongruent = 0
        for i in 0..<K.n {
            let r = Int(f.coeffs[i])
            if r < 0 || r >= K.q { outOfRange += 1 }
            if ((r - Int(p.coeffs[i])) % K.q) != 0 { notCongruent += 1 }
        }
        print("DIAG freeze out-of-range: \(outOfRange), not-congruent: \(notCongruent)")
        XCTAssertEqual(outOfRange, 0)
        XCTAssertEqual(notCongruent, 0)
    }

    // polyToBytes/polyFromBytes must round-trip any reduced polynomial exactly.
    func testPolyByteRoundTrip() {
        var p = K.Poly()
        for i in 0..<K.n { p.coeffs[i] = Int16((i * 37) % K.q) }
        let back = K.polyFromBytes(K.polyToBytes(p))
        XCTAssertEqual(p.coeffs, back.coeffs)
    }
}
