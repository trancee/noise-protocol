import Foundation

// MARK: - BLAKE2s (32-byte digest, RFC 7693)

/// BLAKE2s hash function: 32-bit words, 10 rounds, 64-byte blocks.
public enum BLAKE2s {
    private static let iv: [UInt32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    private static let blockSize = 64
    private static let rounds = 10
    // Rotation constants: 16, 12, 8, 7
    private static let r1: UInt32 = 16
    private static let r2: UInt32 = 12
    private static let r3: UInt32 = 8
    private static let r4: UInt32 = 7

    /// Compute BLAKE2s hash of data, returning 32 bytes.
    public static func hash(_ data: Data) -> Data {
        let digestLen = 32
        // Initialize state: h = IV, then XOR parameter block into h[0]
        var h = iv
        // Parameter block: depth=1, fanout=1, digest_length=digestLen
        h[0] ^= 0x01010000 ^ UInt32(digestLen)

        var bytesCompressed: UInt64 = 0
        let totalLen = data.count
        var offset = 0

        // Process all complete blocks except possibly the last
        while totalLen - offset > blockSize {
            bytesCompressed += UInt64(blockSize)
            compress(&h, block: data, offset: offset, t: bytesCompressed, last: false)
            offset += blockSize
        }

        // Final block (padded with zeros)
        let remaining = totalLen - offset
        bytesCompressed += UInt64(remaining)
        var lastBlock = Data(repeating: 0, count: blockSize)
        if remaining > 0 {
            lastBlock.replaceSubrange(0..<remaining, with: data[offset..<(offset + remaining)])
        }
        compress(&h, block: lastBlock, offset: 0, t: bytesCompressed, last: true)

        // Serialize output
        var result = Data(capacity: digestLen)
        for i in 0..<(digestLen / 4) {
            var word = h[i].littleEndian
            result.append(contentsOf: withUnsafeBytes(of: &word) { Data($0) })
        }
        return result
    }

    private static func compress(_ h: inout [UInt32], block: Data, offset: Int, t: UInt64, last: Bool) {
        // Load message words
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            let start = offset + i * 4
            m[i] = block.withUnsafeBytes { buf in
                buf.load(fromByteOffset: start, as: UInt32.self)
            }.littleEndian
        }

        // Initialize local state
        var v = [UInt32](repeating: 0, count: 16)
        for i in 0..<8 { v[i] = h[i] }
        v[8] = iv[0]
        v[9] = iv[1]
        v[10] = iv[2]
        v[11] = iv[3]
        v[12] = iv[4] ^ UInt32(truncatingIfNeeded: t)
        v[13] = iv[5] ^ UInt32(truncatingIfNeeded: t >> 32)
        v[14] = last ? iv[6] ^ 0xFFFFFFFF : iv[6]
        v[15] = iv[7]

        // Rounds
        for round in 0..<rounds {
            let s = sigma[round]
            g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        // Finalize
        for i in 0..<8 {
            h[i] = h[i] ^ v[i] ^ v[i + 8]
        }
    }

    private static func g(_ v: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotateRight(r1)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(r2)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotateRight(r3)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(r4)
    }
}

// MARK: - BLAKE2b (64-byte digest, RFC 7693)

/// BLAKE2b hash function: 64-bit words, 12 rounds, 128-byte blocks.
public enum BLAKE2b {
    private static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        // Rounds 10-11 wrap to rows 0-1
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ]

    private static let blockSize = 128
    private static let rounds = 12
    // Rotation constants: 32, 24, 16, 63
    private static let r1: UInt64 = 32
    private static let r2: UInt64 = 24
    private static let r3: UInt64 = 16
    private static let r4: UInt64 = 63

    /// Compute BLAKE2b hash of data, returning 64 bytes.
    public static func hash(_ data: Data) -> Data {
        let digestLen = 64
        var h = iv
        h[0] ^= 0x01010000 ^ UInt64(digestLen)

        var bytesCompressed: UInt64 = 0
        let totalLen = data.count
        var offset = 0

        while totalLen - offset > blockSize {
            bytesCompressed += UInt64(blockSize)
            compress(&h, block: data, offset: offset, t: bytesCompressed, last: false)
            offset += blockSize
        }

        let remaining = totalLen - offset
        bytesCompressed += UInt64(remaining)
        var lastBlock = Data(repeating: 0, count: blockSize)
        if remaining > 0 {
            lastBlock.replaceSubrange(0..<remaining, with: data[offset..<(offset + remaining)])
        }
        compress(&h, block: lastBlock, offset: 0, t: bytesCompressed, last: true)

        var result = Data(capacity: digestLen)
        for i in 0..<(digestLen / 8) {
            var word = h[i].littleEndian
            result.append(contentsOf: withUnsafeBytes(of: &word) { Data($0) })
        }
        return result
    }

    private static func compress(_ h: inout [UInt64], block: Data, offset: Int, t: UInt64, last: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        for i in 0..<16 {
            let start = offset + i * 8
            m[i] = block.withUnsafeBytes { buf in
                buf.load(fromByteOffset: start, as: UInt64.self)
            }.littleEndian
        }

        var v = [UInt64](repeating: 0, count: 16)
        for i in 0..<8 { v[i] = h[i] }
        v[8] = iv[0]
        v[9] = iv[1]
        v[10] = iv[2]
        v[11] = iv[3]
        v[12] = iv[4] ^ t
        v[13] = iv[5]  // High word of counter, 0 for messages < 2^64
        v[14] = last ? iv[6] ^ 0xFFFFFFFFFFFFFFFF : iv[6]
        v[15] = iv[7]

        for round in 0..<rounds {
            let s = sigma[round]
            g(&v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(&v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(&v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(&v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(&v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(&v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(&v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(&v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for i in 0..<8 {
            h[i] = h[i] ^ v[i] ^ v[i + 8]
        }
    }

    private static func g(_ v: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
        v[a] = v[a] &+ v[b] &+ x
        v[d] = (v[d] ^ v[a]).rotateRight(r1)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(r2)
        v[a] = v[a] &+ v[b] &+ y
        v[d] = (v[d] ^ v[a]).rotateRight(r3)
        v[c] = v[c] &+ v[d]
        v[b] = (v[b] ^ v[c]).rotateRight(r4)
    }
}

// MARK: - Rotate helpers

extension UInt32 {
    func rotateRight(_ n: UInt32) -> UInt32 {
        (self >> n) | (self << (32 - n))
    }
}

extension UInt64 {
    func rotateRight(_ n: UInt64) -> UInt64 {
        (self >> n) | (self << (64 - n))
    }
}
