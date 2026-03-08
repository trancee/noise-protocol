import Foundation

private protocol NoiseDigestPrimitive {
    var digestLength: Int { get }
    var blockLength: Int { get }
    func digest(_ data: Data) -> Data
}

private func noiseDigestHKDF<D: NoiseDigestPrimitive>(
    chainingKey: Data,
    inputKeyMaterial: Data,
    outputCount: Int,
    digest: D
) -> [Data] {
    guard outputCount > 0, outputCount <= Int(UInt8.max) else {
        return []
    }

    let tempKey = noiseHMAC(key: chainingKey, data: inputKeyMaterial, digest: digest)
    var outputs: [Data] = []
    outputs.reserveCapacity(outputCount)

    var previous = Data()
    for counter in 1...outputCount {
        var input = Data()
        input.reserveCapacity(previous.count + 1)
        input.append(previous)
        input.append(UInt8(counter))
        previous = noiseHMAC(key: tempKey, data: input, digest: digest)
        outputs.append(previous)
    }

    return outputs
}

private func noiseHMAC<D: NoiseDigestPrimitive>(key: Data, data: Data, digest: D) -> Data {
    let material = key.count > digest.blockLength ? digest.digest(key) : key
    var normalizedKey = Data(repeating: 0, count: digest.blockLength)
    normalizedKey.replaceSubrange(0..<material.count, with: material)

    let outerPad = Data(normalizedKey.map { $0 ^ 0x5c })
    let innerPad = Data(normalizedKey.map { $0 ^ 0x36 })

    let innerHash = digest.digest(innerPad + data)
    return digest.digest(outerPad + innerHash)
}

public struct Blake2sHashAdapter: NoiseHashAdapter {
    private static let digest = Blake2sDigest()

    public let name: String = "BLAKE2s"
    public let hashLength: Int = 32

    public init() {}

    public func hash(_ data: Data) -> Data {
        Self.digest.digest(data)
    }

    public func hkdf(chainingKey: Data, inputKeyMaterial: Data, outputCount: Int) -> [Data] {
        noiseDigestHKDF(
            chainingKey: chainingKey,
            inputKeyMaterial: inputKeyMaterial,
            outputCount: outputCount,
            digest: Self.digest
        )
    }
}

public struct Blake2bHashAdapter: NoiseHashAdapter {
    private static let digest = Blake2bDigest()

    public let name: String = "BLAKE2b"
    public let hashLength: Int = 64

    public init() {}

    public func hash(_ data: Data) -> Data {
        Self.digest.digest(data)
    }

    public func hkdf(chainingKey: Data, inputKeyMaterial: Data, outputCount: Int) -> [Data] {
        noiseDigestHKDF(
            chainingKey: chainingKey,
            inputKeyMaterial: inputKeyMaterial,
            outputCount: outputCount,
            digest: Self.digest
        )
    }
}

private struct Blake2sDigest: NoiseDigestPrimitive {
    let digestLength = 32
    let blockLength = 64

    func digest(_ data: Data) -> Data {
        var state = blake2sIV
        state[0] ^= 0x0101_0020

        var t0: UInt32 = 0
        var t1: UInt32 = 0
        var offset = 0

        while offset + blockLength < data.count {
            let block = Data(data[offset..<(offset + blockLength)])
            offset += blockLength
            let previous = t0
            t0 &+= UInt32(blockLength)
            if t0 < previous {
                t1 &+= 1
            }
            blake2sCompress(state: &state, block: block, t0: t0, t1: t1, isLast: false)
        }

        let remaining = data.count - offset
        var finalBlock = Data(repeating: 0, count: blockLength)
        if remaining > 0 {
            finalBlock.replaceSubrange(0..<remaining, with: data[offset..<data.count])
        }
        let previous = t0
        t0 &+= UInt32(remaining)
        if t0 < previous {
            t1 &+= 1
        }
        blake2sCompress(state: &state, block: finalBlock, t0: t0, t1: t1, isLast: true)

        var output = Data(repeating: 0, count: digestLength)
        for index in state.indices {
            writeUInt32LittleEndian(&output, offset: index * 4, value: state[index])
        }
        return output
    }
}

private struct Blake2bDigest: NoiseDigestPrimitive {
    let digestLength = 64
    let blockLength = 128

    func digest(_ data: Data) -> Data {
        var state = blake2bIV
        state[0] ^= 0x0101_0040

        var t0: UInt64 = 0
        var t1: UInt64 = 0
        var offset = 0

        while offset + blockLength < data.count {
            let block = Data(data[offset..<(offset + blockLength)])
            offset += blockLength
            let previous = t0
            t0 &+= UInt64(blockLength)
            if t0 < previous {
                t1 &+= 1
            }
            blake2bCompress(state: &state, block: block, t0: t0, t1: t1, isLast: false)
        }

        let remaining = data.count - offset
        var finalBlock = Data(repeating: 0, count: blockLength)
        if remaining > 0 {
            finalBlock.replaceSubrange(0..<remaining, with: data[offset..<data.count])
        }
        let previous = t0
        t0 &+= UInt64(remaining)
        if t0 < previous {
            t1 &+= 1
        }
        blake2bCompress(state: &state, block: finalBlock, t0: t0, t1: t1, isLast: true)

        var output = Data(repeating: 0, count: digestLength)
        for index in state.indices {
            writeUInt64LittleEndian(&output, offset: index * 8, value: state[index])
        }
        return output
    }
}

private func blake2sCompress(state: inout [UInt32], block: Data, t0: UInt32, t1: UInt32, isLast: Bool) {
    var message = [UInt32](repeating: 0, count: 16)
    for index in 0..<16 {
        message[index] = readUInt32LittleEndian(block, offset: index * 4)
    }

    var vector = [UInt32](repeating: 0, count: 16)
    for index in 0..<8 {
        vector[index] = state[index]
        vector[index + 8] = blake2sIV[index]
    }
    vector[12] ^= t0
    vector[13] ^= t1
    if isLast {
        vector[14] ^= UInt32.max
    }

    for round in 0..<10 {
        let sigma = blake2Sigma[round]
        blake2sMix(&vector, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]])
        blake2sMix(&vector, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]])
        blake2sMix(&vector, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]])
        blake2sMix(&vector, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]])
        blake2sMix(&vector, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]])
        blake2sMix(&vector, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]])
        blake2sMix(&vector, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]])
        blake2sMix(&vector, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]])
    }

    for index in 0..<8 {
        state[index] ^= vector[index] ^ vector[index + 8]
    }
}

private func blake2sMix(_ vector: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt32, _ y: UInt32) {
    vector[a] = vector[a] &+ vector[b] &+ x
    vector[d] = (vector[d] ^ vector[a]).rotatedRight(16)
    vector[c] = vector[c] &+ vector[d]
    vector[b] = (vector[b] ^ vector[c]).rotatedRight(12)
    vector[a] = vector[a] &+ vector[b] &+ y
    vector[d] = (vector[d] ^ vector[a]).rotatedRight(8)
    vector[c] = vector[c] &+ vector[d]
    vector[b] = (vector[b] ^ vector[c]).rotatedRight(7)
}

private func blake2bCompress(state: inout [UInt64], block: Data, t0: UInt64, t1: UInt64, isLast: Bool) {
    var message = [UInt64](repeating: 0, count: 16)
    for index in 0..<16 {
        message[index] = readUInt64LittleEndian(block, offset: index * 8)
    }

    var vector = [UInt64](repeating: 0, count: 16)
    for index in 0..<8 {
        vector[index] = state[index]
        vector[index + 8] = blake2bIV[index]
    }
    vector[12] ^= t0
    vector[13] ^= t1
    if isLast {
        vector[14] ^= UInt64.max
    }

    for round in 0..<12 {
        let sigma = blake2Sigma[round]
        blake2bMix(&vector, 0, 4, 8, 12, message[sigma[0]], message[sigma[1]])
        blake2bMix(&vector, 1, 5, 9, 13, message[sigma[2]], message[sigma[3]])
        blake2bMix(&vector, 2, 6, 10, 14, message[sigma[4]], message[sigma[5]])
        blake2bMix(&vector, 3, 7, 11, 15, message[sigma[6]], message[sigma[7]])
        blake2bMix(&vector, 0, 5, 10, 15, message[sigma[8]], message[sigma[9]])
        blake2bMix(&vector, 1, 6, 11, 12, message[sigma[10]], message[sigma[11]])
        blake2bMix(&vector, 2, 7, 8, 13, message[sigma[12]], message[sigma[13]])
        blake2bMix(&vector, 3, 4, 9, 14, message[sigma[14]], message[sigma[15]])
    }

    for index in 0..<8 {
        state[index] ^= vector[index] ^ vector[index + 8]
    }
}

private func blake2bMix(_ vector: inout [UInt64], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
    vector[a] = vector[a] &+ vector[b] &+ x
    vector[d] = (vector[d] ^ vector[a]).rotatedRight(32)
    vector[c] = vector[c] &+ vector[d]
    vector[b] = (vector[b] ^ vector[c]).rotatedRight(24)
    vector[a] = vector[a] &+ vector[b] &+ y
    vector[d] = (vector[d] ^ vector[a]).rotatedRight(16)
    vector[c] = vector[c] &+ vector[d]
    vector[b] = (vector[b] ^ vector[c]).rotatedRight(63)
}

private let blake2sIV: [UInt32] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

private let blake2bIV: [UInt64] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
]

private let blake2Sigma: [[Int]] = [
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
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
]

private func readUInt32LittleEndian(_ data: Data, offset: Int) -> UInt32 {
    UInt32(data[offset]) |
        (UInt32(data[offset + 1]) << 8) |
        (UInt32(data[offset + 2]) << 16) |
        (UInt32(data[offset + 3]) << 24)
}

private func writeUInt32LittleEndian(_ data: inout Data, offset: Int, value: UInt32) {
    data[offset] = UInt8(truncatingIfNeeded: value)
    data[offset + 1] = UInt8(truncatingIfNeeded: value >> 8)
    data[offset + 2] = UInt8(truncatingIfNeeded: value >> 16)
    data[offset + 3] = UInt8(truncatingIfNeeded: value >> 24)
}

private func readUInt64LittleEndian(_ data: Data, offset: Int) -> UInt64 {
    var result: UInt64 = 0
    for index in 0..<8 {
        result |= UInt64(data[offset + index]) << (index * 8)
    }
    return result
}

private func writeUInt64LittleEndian(_ data: inout Data, offset: Int, value: UInt64) {
    for index in 0..<8 {
        data[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8))
    }
}

private extension UInt32 {
    func rotatedRight(_ count: UInt32) -> UInt32 {
        (self >> count) | (self << (32 - count))
    }
}

private extension UInt64 {
    func rotatedRight(_ count: UInt64) -> UInt64 {
        (self >> count) | (self << (64 - count))
    }
}