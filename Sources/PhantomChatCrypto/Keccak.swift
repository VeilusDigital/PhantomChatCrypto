// Extracted verbatim from Phantom Chat (Veilus Digital) for public review.
// Source-available — see LICENSE. Cryptographic logic is unmodified;
// only imports differ from the in-app file.

import Foundation

// ═══════════════════════════════════════════════════════════════════════
// MARK: - Keccak-f[1600] + SHAKE128/256 (FIPS 202)
// ═══════════════════════════════════════════════════════════════════════
//
// Apple's CryptoKit ships SHA3-256/384/512 but NOT SHAKE128/256, and
// Kyber-768 (used below for PQXDH) needs both — SHAKE128 for matrix
// expansion (XOF) and SHAKE256 for noise sampling (PRF). So we implement
// Keccak ourselves from scratch.
//
// Reference: FIPS 202. Round constants and ρ offsets are the official
// Keccak parameters. Self-test at the end runs SHA3-256/512 and SHAKE
// known-answer tests on first PQXDH use.

// `nonisolated` — pure permutation primitive used by KeccakSponge from
// any context.
nonisolated struct KeccakF1600 {
    var st: [UInt64] = Array(repeating: 0, count: 25)

    private static let rho: [Int] = [
        0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14,
    ]

    private static let piMap: [Int] = [
        0, 10, 20,  5, 15,
        16,  1, 11, 21,  6,
        7, 17,  2, 12, 22,
        23,  8, 18,  3, 13,
        14, 24,  9, 19,  4,
    ]

    private static let rc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]

    @inline(__always)
    private static func rotl(_ x: UInt64, _ n: Int) -> UInt64 {
        let s = n & 63
        if s == 0 { return x }
        return (x &<< s) | (x &>> (64 - s))
    }

    mutating func permute() {
        var a = st
        var c = [UInt64](repeating: 0, count: 5)
        var d = [UInt64](repeating: 0, count: 5)
        var b = [UInt64](repeating: 0, count: 25)

        for round in 0..<24 {
            for x in 0..<5 {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]
            }
            for x in 0..<5 {
                d[x] = c[(x + 4) % 5] ^ Self.rotl(c[(x + 1) % 5], 1)
            }
            for i in 0..<25 {
                a[i] ^= d[i % 5]
            }
            for i in 0..<25 {
                b[Self.piMap[i]] = Self.rotl(a[i], Self.rho[i])
            }
            for y in 0..<5 {
                let yi = 5 * y
                let b0 = b[yi]; let b1 = b[yi + 1]; let b2 = b[yi + 2]
                let b3 = b[yi + 3]; let b4 = b[yi + 4]
                a[yi]     = b0 ^ ((~b1) & b2)
                a[yi + 1] = b1 ^ ((~b2) & b3)
                a[yi + 2] = b2 ^ ((~b3) & b4)
                a[yi + 3] = b3 ^ ((~b4) & b0)
                a[yi + 4] = b4 ^ ((~b0) & b1)
            }
            a[0] ^= Self.rc[round]
        }
        st = a
    }
}

// `nonisolated` — pure stateless sponge primitives, used by PCKeccak
// and the Kyber implementation from any actor context.
nonisolated struct KeccakSponge {
    private var state: KeccakF1600
    private let rateInBytes: Int
    private let domainSeparator: UInt8
    private var absorbBuffer: [UInt8]
    private var absorbed: Bool = false
    private var squeezeBuffer: [UInt8]
    private var squeezeOffset: Int

    init(rateInBytes: Int, domainSeparator: UInt8) {
        self.state = KeccakF1600()
        self.rateInBytes = rateInBytes
        self.domainSeparator = domainSeparator
        self.absorbBuffer = []
        self.squeezeBuffer = []
        self.squeezeOffset = 0
    }

    mutating func absorb(_ data: [UInt8]) {
        precondition(!absorbed)
        absorbBuffer.append(contentsOf: data)
        while absorbBuffer.count >= rateInBytes {
            xorIntoState(Array(absorbBuffer.prefix(rateInBytes)))
            absorbBuffer.removeFirst(rateInBytes)
            state.permute()
        }
    }

    private mutating func finalizeAbsorb() {
        guard !absorbed else { return }
        absorbed = true
        var pad = absorbBuffer
        pad.append(domainSeparator)
        while pad.count < rateInBytes { pad.append(0) }
        pad[rateInBytes - 1] |= 0x80
        xorIntoState(pad)
        state.permute()
        absorbBuffer.removeAll()
        squeezeBuffer = extractRate()
        squeezeOffset = 0
    }

    mutating func squeeze(_ length: Int) -> [UInt8] {
        finalizeAbsorb()
        var out: [UInt8] = []
        out.reserveCapacity(length)
        while out.count < length {
            if squeezeOffset >= squeezeBuffer.count {
                state.permute()
                squeezeBuffer = extractRate()
                squeezeOffset = 0
            }
            let take = min(length - out.count, squeezeBuffer.count - squeezeOffset)
            out.append(contentsOf: squeezeBuffer[squeezeOffset ..< (squeezeOffset + take)])
            squeezeOffset += take
        }
        return out
    }

    private mutating func xorIntoState(_ block: [UInt8]) {
        precondition(block.count == rateInBytes)
        let lanes = rateInBytes / 8
        for i in 0..<lanes {
            var lane: UInt64 = 0
            for j in 0..<8 {
                lane |= UInt64(block[i * 8 + j]) << (8 * j)
            }
            state.st[i] ^= lane
        }
    }

    private func extractRate() -> [UInt8] {
        var out = [UInt8](repeating: 0, count: rateInBytes)
        let lanes = rateInBytes / 8
        for i in 0..<lanes {
            let lane = state.st[i]
            for j in 0..<8 {
                out[i * 8 + j] = UInt8((lane >> (8 * j)) & 0xff)
            }
        }
        return out
    }
}

// `nonisolated` — pure stateless hash primitives, called from the Kyber
// implementation, X3DH, PQXDH combiner, and the self-test. Default
// MainActor isolation would have us hopping just to compute a digest.
nonisolated enum PCKeccak {
    static func shake128(_ input: [UInt8], outputBytes: Int) -> [UInt8] {
        var s = KeccakSponge(rateInBytes: 168, domainSeparator: 0x1F)
        s.absorb(input)
        return s.squeeze(outputBytes)
    }
    static func shake256(_ input: [UInt8], outputBytes: Int) -> [UInt8] {
        var s = KeccakSponge(rateInBytes: 136, domainSeparator: 0x1F)
        s.absorb(input)
        return s.squeeze(outputBytes)
    }
    static func sha3_256(_ input: [UInt8]) -> [UInt8] {
        var s = KeccakSponge(rateInBytes: 136, domainSeparator: 0x06)
        s.absorb(input)
        return s.squeeze(32)
    }
    static func sha3_512(_ input: [UInt8]) -> [UInt8] {
        var s = KeccakSponge(rateInBytes: 72, domainSeparator: 0x06)
        s.absorb(input)
        return s.squeeze(64)
    }
    /// Returns a primed sponge for streaming output. Kyber matrix
    /// expansion needs to keep pulling bytes until it has enough valid
    /// coefficients in the rejection sampler.
    static func shake128Streamer(_ input: [UInt8]) -> KeccakSponge {
        var s = KeccakSponge(rateInBytes: 168, domainSeparator: 0x1F)
        s.absorb(input)
        return s
    }
}
