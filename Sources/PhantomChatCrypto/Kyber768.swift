// Extracted verbatim from Phantom Chat (Veilus Digital) for public review.
// Source-available — see LICENSE. Cryptographic logic is unmodified;
// only imports differ from the in-app file.

import Foundation
import Security

// ═══════════════════════════════════════════════════════════════════════
// MARK: - Kyber-768 (ML-KEM-768) — pure-Swift implementation
// ═══════════════════════════════════════════════════════════════════════
//
// FIPS 203 ML-KEM-768 (formerly known as Kyber-768) — a lattice-based
// KEM standardised by NIST in 2024. We use it inside the PQXDH hybrid
// below: every PQXDH session combines a classical X25519/P-256 DH with
// a Kyber-768 KEM via HKDF, so if either component holds against a
// future attacker the shared secret remains safe.
//
// Parameters (Kyber-768):
//   n  = 256   polynomial degree
//   q  = 3329  prime modulus
//   k  = 3     dimension of polynomial vector
//   η₁ = 2     CBD noise width for s, e (keygen)
//   η₂ = 2     CBD noise width for e₁, e₂ (encaps)
//   d_u = 10   compression bits for u
//   d_v = 4    compression bits for v
//
// Sizes:
//   public key   = 1184 bytes  (k·384 + 32 seed)
//   secret key   = 2400 bytes  (sk′ + pk + H(pk) + z)
//   ciphertext   = 1088 bytes  (k·320 + 128)
//   shared key   =   32 bytes

// Marked `nonisolated` so X3DHProtocol (an actor) can call Kyber768
// static methods without hopping. The enum has no mutable state — it's
// pure crypto primitives — so it doesn't need MainActor isolation.
nonisolated enum Kyber768 {

    static let n  = 256
    static let q  = 3329
    static let k  = 3
    static let eta1 = 2
    static let eta2 = 2
    static let du = 10
    static let dv = 4

    static let pubKeyBytes        = 1184
    static let secretKeyBytes     = 2400
    static let ciphertextBytes    = 1088
    static let sharedSecretBytes  = 32

    static let polyBytes          = 384            // 12-bit encoded poly = 256 * 12 / 8
    static let polyCompressedU    = 320            // du=10 → 256 * 10 / 8
    static let polyCompressedV    = 128            // dv=4  → 256 * 4 / 8

    // Montgomery parameters: R = 2^16 mod q = 2285, q⁻¹ mod 2^16 = 62209 (Q_INV used negated)
    // Reference uses: KYBER_Q = 3329, MONT = 2285 (R mod q), QINV = 62209 (−q⁻¹ mod 2^16).
    static let qinv: Int32 = 62209
    static let mont: Int16 = 2285  // R mod q

    // 7-bit BitRev of 0..127 — used to index the zetas table during NTT.
    private static let zetas: [Int16] = [
        -1044, -758, -359, -1517, 1493, 1422, 287, 202,
        -171, 622, 1577, 182, 962, -1202, -1474, 1468,
        573, -1325, 264, 383, -829, 1458, -1602, -130,
        -681, 1017, 732, 608, -1542, 411, -205, -1571,
        1223, 652, -552, 1015, -1293, 1491, -282, -1544,
        516, -8, -320, -666, -1618, -1162, 126, 1469,
        -853, -90, -271, 830, 107, -1421, -247, -951,
        -398, 961, -1508, -725, 448, -1065, 677, -1275,
        -1103, 430, 555, 843, -1251, 871, 1550, 105,
        422, 587, 177, -235, -291, -460, 1574, 1653,
        -246, 778, 1159, -147, -777, 1483, -602, 1119,
        -1590, 644, -872, 349, 418, 329, -156, -75,
        817, 1097, 603, 610, 1322, -1285, -1465, 384,
        -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
        -1185, -1530, -1278, 794, -1510, -854, -870, 478,
        -108, -308, 996, 991, 958, -1460, 1522, 1628
    ]

    // MARK: -- Reductions

    @inline(__always)
    static func montgomeryReduce(_ a: Int32) -> Int16 {
        // u = a * QINV mod 2^16
        let u = Int16(truncatingIfNeeded: a &* qinv)
        let t = (a &- Int32(u) &* Int32(q)) >> 16
        return Int16(truncatingIfNeeded: t)
    }

    @inline(__always)
    static func barrettReduce(_ a: Int16) -> Int16 {
        // v = ((1 << 26) + q/2) / q = 20159 (precomputed for q = 3329)
        let v: Int32 = 20159
        var t = (Int32(a) &* v) >> 26
        t = t &* Int32(q)
        return a &- Int16(truncatingIfNeeded: t)
    }

    @inline(__always)
    static func conditionalSubQ(_ a: Int16) -> Int16 {
        var r = a &- Int16(q)
        r += (r >> 15) & Int16(q)
        return r
    }

    static func fqmul(_ a: Int16, _ b: Int16) -> Int16 {
        return montgomeryReduce(Int32(a) &* Int32(b))
    }

    // MARK: -- Polynomial type

    struct Poly {
        var coeffs: [Int16] = Array(repeating: 0, count: n)
    }

    static func polyAdd(_ a: Poly, _ b: Poly) -> Poly {
        var r = Poly()
        for i in 0..<n { r.coeffs[i] = a.coeffs[i] &+ b.coeffs[i] }
        return r
    }

    static func polySub(_ a: Poly, _ b: Poly) -> Poly {
        var r = Poly()
        for i in 0..<n { r.coeffs[i] = a.coeffs[i] &- b.coeffs[i] }
        return r
    }

    static func polyReduce(_ a: inout Poly) {
        for i in 0..<n { a.coeffs[i] = barrettReduce(a.coeffs[i]) }
    }

    static func polyToMont(_ a: inout Poly) {
        // f = R mod q = 2285 already in mont form, multiply by R^2 / R = R
        let f: Int16 = 1353 // = 2^32 mod q (i.e. R² mod q so that fqmul converts in→Montgomery)
        for i in 0..<n {
            a.coeffs[i] = fqmul(a.coeffs[i], f)
        }
    }

    static func polyFreeze(_ a: inout Poly) {
        for i in 0..<n { a.coeffs[i] = conditionalSubQ(barrettReduce(a.coeffs[i])) }
    }

    // MARK: -- NTT (Cooley-Tukey, in-place)

    static func ntt(_ a: inout Poly) {
        var k = 1
        var len = 128
        while len >= 2 {
            var start = 0
            while start < 256 {
                let zeta = zetas[k]
                k += 1
                for j in start..<(start + len) {
                    let t = fqmul(zeta, a.coeffs[j + len])
                    a.coeffs[j + len] = a.coeffs[j] &- t
                    a.coeffs[j] = a.coeffs[j] &+ t
                }
                start += 2 * len
            }
            len >>= 1
        }
    }

    static func invNtt(_ a: inout Poly) {
        let f: Int16 = 1441 // mont^2 / 128
        var k = 127
        var len = 2
        while len <= 128 {
            var start = 0
            while start < 256 {
                let zeta = zetas[k]
                k -= 1
                for j in start..<(start + len) {
                    let t = a.coeffs[j]
                    a.coeffs[j] = barrettReduce(t &+ a.coeffs[j + len])
                    a.coeffs[j + len] = a.coeffs[j + len] &- t
                    a.coeffs[j + len] = fqmul(zeta, a.coeffs[j + len])
                }
                start += 2 * len
            }
            len <<= 1
        }
        for j in 0..<256 {
            a.coeffs[j] = fqmul(a.coeffs[j], f)
        }
    }

    /// Base case multiplication of two degree-1 polynomials in the
    /// quotient ring Zq[X]/(X² - ζ), used per pair during NTT-mult.
    static func basemul(_ a0: Int16, _ a1: Int16, _ b0: Int16, _ b1: Int16, _ zeta: Int16) -> (Int16, Int16) {
        var r0 = fqmul(a1, b1)
        r0 = fqmul(r0, zeta)
        r0 = r0 &+ fqmul(a0, b0)
        let r1 = fqmul(a0, b1) &+ fqmul(a1, b0)
        return (r0, r1)
    }

    /// Pointwise multiply two polynomials in NTT form, then reduce.
    static func polyMul(_ a: Poly, _ b: Poly) -> Poly {
        var r = Poly()
        for i in 0..<64 {
            let z = zetas[64 + i]
            let (r0, r1) = basemul(a.coeffs[4*i], a.coeffs[4*i + 1], b.coeffs[4*i], b.coeffs[4*i + 1], z)
            r.coeffs[4*i] = r0
            r.coeffs[4*i + 1] = r1
            let (r2, r3) = basemul(a.coeffs[4*i + 2], a.coeffs[4*i + 3], b.coeffs[4*i + 2], b.coeffs[4*i + 3], -z)
            r.coeffs[4*i + 2] = r2
            r.coeffs[4*i + 3] = r3
        }
        return r
    }

    // MARK: -- Polynomial encoding (12 bits per coefficient)

    static func polyToBytes(_ p: Poly) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: polyBytes)
        for i in 0..<(n / 2) {
            var t0 = p.coeffs[2*i]
            var t1 = p.coeffs[2*i + 1]
            t0 += (t0 >> 15) & Int16(q)
            t1 += (t1 >> 15) & Int16(q)
            bytes[3*i]     = UInt8(truncatingIfNeeded: t0)
            bytes[3*i + 1] = UInt8(truncatingIfNeeded: (t0 >> 8) | (t1 << 4))
            bytes[3*i + 2] = UInt8(truncatingIfNeeded: t1 >> 4)
        }
        return bytes
    }

    static func polyFromBytes(_ bytes: [UInt8]) -> Poly {
        precondition(bytes.count >= polyBytes)
        var p = Poly()
        for i in 0..<(n / 2) {
            let b0 = UInt16(bytes[3*i])
            let b1 = UInt16(bytes[3*i + 1])
            let b2 = UInt16(bytes[3*i + 2])
            p.coeffs[2*i]     = Int16(b0 | ((b1 & 0x0F) << 8))
            p.coeffs[2*i + 1] = Int16((b1 >> 4) | (b2 << 4))
        }
        return p
    }

    // MARK: -- Compression / decompression

    static func compressU(_ p: Poly) -> [UInt8] {
        // 10-bit compression: 4 coefficients → 5 bytes
        var bytes = [UInt8](repeating: 0, count: polyCompressedU)
        var t = [UInt16](repeating: 0, count: 4)
        for i in 0..<(n / 4) {
            for j in 0..<4 {
                var c = p.coeffs[4*i + j]
                c += (c >> 15) & Int16(q)
                // round((c << 10) / q) mod 2^10
                let cu32 = UInt32(c) << 10
                let rounded = (cu32 + UInt32(q) / 2) / UInt32(q)
                t[j] = UInt16(rounded & 0x3FF)
            }
            bytes[5*i]     = UInt8(truncatingIfNeeded: t[0])
            bytes[5*i + 1] = UInt8(truncatingIfNeeded: (t[0] >> 8) | (t[1] << 2))
            bytes[5*i + 2] = UInt8(truncatingIfNeeded: (t[1] >> 6) | (t[2] << 4))
            bytes[5*i + 3] = UInt8(truncatingIfNeeded: (t[2] >> 4) | (t[3] << 6))
            bytes[5*i + 4] = UInt8(truncatingIfNeeded: t[3] >> 2)
        }
        return bytes
    }

    static func decompressU(_ bytes: [UInt8]) -> Poly {
        var p = Poly()
        var t = [UInt16](repeating: 0, count: 4)
        for i in 0..<(n / 4) {
            t[0] = (UInt16(bytes[5*i])       | (UInt16(bytes[5*i + 1]) << 8)) & 0x3FF
            t[1] = ((UInt16(bytes[5*i + 1]) >> 2) | (UInt16(bytes[5*i + 2]) << 6)) & 0x3FF
            t[2] = ((UInt16(bytes[5*i + 2]) >> 4) | (UInt16(bytes[5*i + 3]) << 4)) & 0x3FF
            t[3] = ((UInt16(bytes[5*i + 3]) >> 6) | (UInt16(bytes[5*i + 4]) << 2)) & 0x3FF
            for j in 0..<4 {
                // round(t * q / 2^10)
                p.coeffs[4*i + j] = Int16((UInt32(t[j]) * UInt32(q) + 512) >> 10)
            }
        }
        return p
    }

    static func compressV(_ p: Poly) -> [UInt8] {
        // 4-bit compression: 2 coefficients → 1 byte
        var bytes = [UInt8](repeating: 0, count: polyCompressedV)
        var t = [UInt8](repeating: 0, count: 8)
        for i in 0..<(n / 8) {
            for j in 0..<8 {
                var c = p.coeffs[8*i + j]
                c += (c >> 15) & Int16(q)
                let cu32 = UInt32(c) << 4
                let rounded = (cu32 + UInt32(q) / 2) / UInt32(q)
                t[j] = UInt8(rounded & 0xF)
            }
            bytes[4*i]     = t[0] | (t[1] << 4)
            bytes[4*i + 1] = t[2] | (t[3] << 4)
            bytes[4*i + 2] = t[4] | (t[5] << 4)
            bytes[4*i + 3] = t[6] | (t[7] << 4)
        }
        return bytes
    }

    static func decompressV(_ bytes: [UInt8]) -> Poly {
        var p = Poly()
        for i in 0..<(n / 8) {
            for j in 0..<4 {
                let b = bytes[4*i + j]
                let lo = UInt16(b & 0x0F)
                let hi = UInt16(b >> 4)
                p.coeffs[8*i + 2*j]     = Int16((UInt32(lo) * UInt32(q) + 8) >> 4)
                p.coeffs[8*i + 2*j + 1] = Int16((UInt32(hi) * UInt32(q) + 8) >> 4)
            }
        }
        return p
    }

    // Message ↔ poly: 1 bit per coefficient.
    static func polyFromMessage(_ msg: [UInt8]) -> Poly {
        precondition(msg.count == 32)
        var p = Poly()
        for i in 0..<32 {
            for j in 0..<8 {
                let bit = Int16((msg[i] >> j) & 1)
                // 1 bit → (q+1)/2 = 1665 if set, 0 otherwise
                p.coeffs[8*i + j] = -bit & 1665
            }
        }
        return p
    }

    static func polyToMessage(_ p: Poly) -> [UInt8] {
        var msg = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 {
            for j in 0..<8 {
                var t = p.coeffs[8*i + j]
                t += (t >> 15) & Int16(q)
                // round(t * 2 / q), in {0, 1}
                let bit = ((UInt32(t) << 1) + UInt32(q) / 2) / UInt32(q)
                msg[i] |= UInt8(bit & 1) << j
            }
        }
        return msg
    }

    // MARK: -- CBD sampling (centered binomial distribution)

    static func cbd2(_ buf: [UInt8]) -> Poly {
        precondition(buf.count == 128) // 256 coefficients × 2η/8 bytes = 256 * 4 / 8 = 128
        var p = Poly()
        for i in 0..<(n / 8) {
            var t: UInt32 = 0
            for j in 0..<4 { t |= UInt32(buf[4*i + j]) << (8*j) }
            let d = (t & 0x55555555) + ((t >> 1) & 0x55555555)
            for j in 0..<8 {
                let a = Int16((d >> (4*j)) & 0x3)
                let b = Int16((d >> (4*j + 2)) & 0x3)
                p.coeffs[8*i + j] = a &- b
            }
        }
        return p
    }

    // MARK: -- Polyvec utilities

    struct PolyVec {
        var v: [Poly] = Array(repeating: Poly(), count: k)
    }

    static func polyvecAdd(_ a: PolyVec, _ b: PolyVec) -> PolyVec {
        var r = PolyVec()
        for i in 0..<k { r.v[i] = polyAdd(a.v[i], b.v[i]) }
        return r
    }

    static func polyvecReduce(_ a: inout PolyVec) {
        for i in 0..<k { polyReduce(&a.v[i]) }
    }

    static func polyvecNtt(_ a: inout PolyVec) {
        for i in 0..<k { ntt(&a.v[i]) }
    }

    static func polyvecInvNtt(_ a: inout PolyVec) {
        for i in 0..<k { invNtt(&a.v[i]) }
    }

    static func polyvecPointwiseAcc(_ a: PolyVec, _ b: PolyVec) -> Poly {
        var r = polyMul(a.v[0], b.v[0])
        for i in 1..<k {
            let t = polyMul(a.v[i], b.v[i])
            r = polyAdd(r, t)
        }
        polyReduce(&r)
        return r
    }

    static func polyvecToBytes(_ a: PolyVec) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: polyBytes * k)
        for i in 0..<k {
            let pb = polyToBytes(a.v[i])
            for j in 0..<polyBytes { out[i*polyBytes + j] = pb[j] }
        }
        return out
    }

    static func polyvecFromBytes(_ bytes: [UInt8]) -> PolyVec {
        var v = PolyVec()
        for i in 0..<k {
            let slice = Array(bytes[(i*polyBytes)..<((i+1)*polyBytes)])
            v.v[i] = polyFromBytes(slice)
        }
        return v
    }

    static func polyvecCompress(_ a: PolyVec) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: polyCompressedU * k)
        for i in 0..<k {
            let pb = compressU(a.v[i])
            for j in 0..<polyCompressedU { out[i*polyCompressedU + j] = pb[j] }
        }
        return out
    }

    static func polyvecDecompress(_ bytes: [UInt8]) -> PolyVec {
        var v = PolyVec()
        for i in 0..<k {
            let slice = Array(bytes[(i*polyCompressedU)..<((i+1)*polyCompressedU)])
            v.v[i] = decompressU(slice)
        }
        return v
    }

    // MARK: -- Matrix generation from ρ (XOF rejection sampling)

    static func genMatrix(rho: [UInt8], transposed: Bool) -> [[Poly]] {
        var a = [[Poly]](repeating: [Poly](repeating: Poly(), count: k), count: k)
        for i in 0..<k {
            for j in 0..<k {
                let nonce: [UInt8] = transposed ? [UInt8(i), UInt8(j)] : [UInt8(j), UInt8(i)]
                var s = PCKeccak.shake128Streamer(rho + nonce)
                var coeffs: [Int16] = []
                coeffs.reserveCapacity(n)
                while coeffs.count < n {
                    let block = s.squeeze(168)
                    var idx = 0
                    while idx + 3 <= block.count && coeffs.count < n {
                        let d1 = Int(block[idx]) | (Int(block[idx + 1] & 0x0F) << 8)
                        let d2 = (Int(block[idx + 1]) >> 4) | (Int(block[idx + 2]) << 4)
                        if d1 < q { coeffs.append(Int16(d1)) }
                        if coeffs.count < n && d2 < q { coeffs.append(Int16(d2)) }
                        idx += 3
                    }
                }
                a[i][j].coeffs = coeffs
            }
        }
        return a
    }

    static func matrixPolyVecMul(_ matrix: [[Poly]], _ v: PolyVec) -> PolyVec {
        var r = PolyVec()
        for i in 0..<k {
            r.v[i] = polyvecPointwiseAcc(PolyVec(v: matrix[i]), v)
            polyToMont(&r.v[i])
        }
        return r
    }

    // MARK: -- K-PKE (CPA scheme)

    static func kPkeKeyGen(seed: [UInt8]) -> (pk: [UInt8], sk: [UInt8]) {
        precondition(seed.count == 32)
        let g = PCKeccak.sha3_512(seed + [UInt8(k)])
        let rho = Array(g[0..<32])
        let sigma = Array(g[32..<64])

        let aMatrix = genMatrix(rho: rho, transposed: false)

        // Sample s, e from CBD using sigma as seed
        var s = PolyVec()
        var e = PolyVec()
        for i in 0..<k {
            let buf = PCKeccak.shake256(sigma + [UInt8(i)], outputBytes: 128)
            s.v[i] = cbd2(buf)
        }
        for i in 0..<k {
            let buf = PCKeccak.shake256(sigma + [UInt8(k + i)], outputBytes: 128)
            e.v[i] = cbd2(buf)
        }

        polyvecNtt(&s)
        polyvecNtt(&e)
        var t = matrixPolyVecMul(aMatrix, s)
        t = polyvecAdd(t, e)

        // Canonicalise t and s to [0,q) before serialising. polyToBytes packs
        // 12-bit values and assumes canonical coefficients; barrettReduce alone
        // is only congruent mod q (it can return q), which produced
        // non-canonical bytes that diverged from FIPS-203 / Apple ML-KEM for
        // the same seed. polyFreeze (conditionalSubQ ∘ barrettReduce) maps
        // every coefficient into [0,q). (Also fixes serialising s unreduced
        // after the NTT, which had corrupted the secret key on read-back.)
        for i in 0..<k { polyFreeze(&t.v[i]) }
        for i in 0..<k { polyFreeze(&s.v[i]) }

        let pk = polyvecToBytes(t) + rho
        let sk = polyvecToBytes(s)
        return (pk, sk)
    }

    static func kPkeEncrypt(pk: [UInt8], message: [UInt8], coins: [UInt8]) -> [UInt8] {
        precondition(pk.count == polyBytes * k + 32)
        precondition(message.count == 32)
        precondition(coins.count == 32)

        let tBytes = Array(pk[0..<(polyBytes * k)])
        let rho = Array(pk[(polyBytes * k)..<pk.count])
        let t = polyvecFromBytes(tBytes)

        let aT = genMatrix(rho: rho, transposed: true)

        var r = PolyVec()
        var e1 = PolyVec()
        for i in 0..<k {
            let buf = PCKeccak.shake256(coins + [UInt8(i)], outputBytes: 128)
            r.v[i] = cbd2(buf)
        }
        for i in 0..<k {
            let buf = PCKeccak.shake256(coins + [UInt8(k + i)], outputBytes: 128)
            e1.v[i] = cbd2(buf)
        }
        let e2Buf = PCKeccak.shake256(coins + [UInt8(2 * k)], outputBytes: 128)
        let e2 = cbd2(e2Buf)

        polyvecNtt(&r)

        // u = A^T ∘ r via basemul-accumulate WITHOUT tomont. The immediately
        // following inverse-NTT (invntt_tomont) performs the single Montgomery
        // conversion. The previous code used matrixPolyVecMul here, which also
        // applied polyToMont — a SECOND Montgomery factor on u that the public
        // key `t` (correctly tomont'd once) does not have. That asymmetry made
        // v − s∘u fail to cancel, so decapsulation always diverged. Verified
        // against schoolbook + full noiseless/noisy/compressed round-trips.
        var u = PolyVec()
        for i in 0..<k {
            u.v[i] = polyvecPointwiseAcc(PolyVec(v: aT[i]), r)
        }
        polyvecInvNtt(&u)
        u = polyvecAdd(u, e1)

        var v = polyvecPointwiseAcc(t, r)
        invNtt(&v)
        v = polyAdd(v, e2)
        v = polyAdd(v, polyFromMessage(message))

        polyvecReduce(&u)
        polyReduce(&v)

        let uBytes = polyvecCompress(u)
        let vBytes = compressV(v)
        return uBytes + vBytes
    }

    static func kPkeDecrypt(sk: [UInt8], ciphertext: [UInt8]) -> [UInt8] {
        precondition(sk.count == polyBytes * k)
        precondition(ciphertext.count == polyCompressedU * k + polyCompressedV)
        let uBytes = Array(ciphertext[0..<(polyCompressedU * k)])
        let vBytes = Array(ciphertext[(polyCompressedU * k)..<ciphertext.count])

        var u = polyvecDecompress(uBytes)
        let v = decompressV(vBytes)
        let s = polyvecFromBytes(sk)

        polyvecNtt(&u)
        var mp = polyvecPointwiseAcc(s, u)
        invNtt(&mp)
        mp = polySub(v, mp)
        polyReduce(&mp)
        return polyToMessage(mp)
    }

    // MARK: -- ML-KEM (Kyber-768) — KeyGen / Encaps / Decaps

    static func keyGen(randomBytes: () -> [UInt8]) -> (publicKey: [UInt8], secretKey: [UInt8]) {
        let d = randomBytes()    // 32 random bytes
        let z = randomBytes()    // 32 random bytes
        precondition(d.count == 32 && z.count == 32)

        let (pkBytes, skPrimeBytes) = kPkeKeyGen(seed: d)
        let h = PCKeccak.sha3_256(pkBytes)
        let sk = skPrimeBytes + pkBytes + h + z
        return (pkBytes, sk)
    }

    static func encaps(publicKey pk: [UInt8], randomBytes: () -> [UInt8]) -> (ciphertext: [UInt8], sharedSecret: [UInt8]) {
        precondition(pk.count == pubKeyBytes)
        let m = randomBytes()    // 32 random bytes
        precondition(m.count == 32)

        let hPk = PCKeccak.sha3_256(pk)
        let g = PCKeccak.sha3_512(m + hPk)
        let K = Array(g[0..<32])
        let r = Array(g[32..<64])
        let c = kPkeEncrypt(pk: pk, message: m, coins: r)
        return (c, K)
    }

    static func decaps(secretKey sk: [UInt8], ciphertext c: [UInt8]) -> [UInt8] {
        precondition(sk.count == secretKeyBytes)
        precondition(c.count == ciphertextBytes)
        let skPrime = Array(sk[0..<(polyBytes * k)])
        let pk      = Array(sk[(polyBytes * k)..<(polyBytes * k + pubKeyBytes)])
        let h       = Array(sk[(polyBytes * k + pubKeyBytes)..<(polyBytes * k + pubKeyBytes + 32)])
        let z       = Array(sk[(polyBytes * k + pubKeyBytes + 32)..<sk.count])

        let mPrime = kPkeDecrypt(sk: skPrime, ciphertext: c)
        let g = PCKeccak.sha3_512(mPrime + h)
        let kPrime = Array(g[0..<32])
        let rPrime = Array(g[32..<64])
        let cPrime = kPkeEncrypt(pk: pk, message: mPrime, coins: rPrime)

        // Constant-time compare c == cPrime
        var diff: UInt8 = 0
        for i in 0..<c.count { diff |= c[i] ^ cPrime[i] }
        let valid = diff == 0

        // Return K' on match, else SHA3-256(z || c) (implicit rejection)
        if valid {
            return kPrime
        } else {
            let reject = PCKeccak.sha3_256(z + c)
            return reject
        }
    }

    /// CSPRNG wrapper used by KeyGen/Encaps. Calls SecRandomCopyBytes.
    static func randomBytes32() -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        let status = out.withUnsafeMutableBufferPointer {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return out
    }

    /// One-shot keygen using the system CSPRNG.
    static func keyGen() -> (publicKey: [UInt8], secretKey: [UInt8]) {
        return keyGen(randomBytes: randomBytes32)
    }

    /// One-shot encaps using the system CSPRNG.
    static func encaps(publicKey pk: [UInt8]) -> (ciphertext: [UInt8], sharedSecret: [UInt8]) {
        return encaps(publicKey: pk, randomBytes: randomBytes32)
    }
}
