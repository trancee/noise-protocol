import BigInt
import Foundation
import NoiseCore

public struct X448DiffieHellmanAdapter: NoiseDeterministicDiffieHellmanAdapter {
    private static let keyLength = 56
    private static let scalarBits = 448
    private static let fieldPrime = (BigUInt(1) << 448) - (BigUInt(1) << 224) - BigUInt(1)
    private static let a24 = BigUInt(39081)
    private static let basePoint = BigUInt(5)
    private static let one = BigUInt(1)
    private static let two = BigUInt(2)

    public let name: String = "448"

    public init() {}

    public func generateKeyPair() throws -> NoiseDHKeyPair {
        let privateKey = Data((0..<Self.keyLength).map { _ in UInt8.random(in: UInt8.min...UInt8.max) })
        return try deriveKeyPair(privateKey: privateKey)
    }

    public func deriveKeyPair(privateKey: Data) throws -> NoiseDHKeyPair {
        try validateLength(privateKey, algorithm: name)

        var scalar = Array(privateKey)
        clampScalar(&scalar)
        let publicKey = scalarMultiply(scalar: scalar, uCoordinate: Self.basePoint)
        return NoiseDHKeyPair(privateKey: Data(scalar), publicKey: publicKey)
    }

    public func dh(privateKey: Data, publicKey: Data) throws -> Data {
        try validateLength(privateKey, algorithm: name)
        try validateLength(publicKey, algorithm: name)

        var scalar = Array(privateKey)
        clampScalar(&scalar)
        let uCoordinate = fromLittleEndian(publicKey) % Self.fieldPrime
        return scalarMultiply(scalar: scalar, uCoordinate: uCoordinate)
    }

    private func validateLength(_ bytes: Data, algorithm: String) throws {
        guard bytes.count == Self.keyLength else {
            throw NoiseCryptoAdapterError.invalidKeyLength(
                algorithm: algorithm,
                expected: Self.keyLength,
                actual: bytes.count
            )
        }
    }

    private func clampScalar(_ scalar: inout [UInt8]) {
        scalar[0] &= 0xFC
        scalar[Self.keyLength - 1] |= 0x80
    }

    private func scalarMultiply(scalar: [UInt8], uCoordinate: BigUInt) -> Data {
        let x1 = uCoordinate % Self.fieldPrime
        var x2 = Self.one
        var z2 = BigUInt(0)
        var x3 = x1
        var z3 = Self.one
        var swapState = 0

        for bitIndex in stride(from: Self.scalarBits - 1, through: 0, by: -1) {
            let currentBit = scalarBit(scalar, bitIndex: bitIndex)
            if swapState != currentBit {
                exchange(&x2, &x3)
                exchange(&z2, &z3)
            }
            swapState = currentBit

            let a = addMod(x2, z2)
            let aa = multiplyMod(a, a)
            let b = subtractMod(x2, z2)
            let bb = multiplyMod(b, b)
            let e = subtractMod(aa, bb)
            let c = addMod(x3, z3)
            let d = subtractMod(x3, z3)
            let da = multiplyMod(d, a)
            let cb = multiplyMod(c, b)
            let daPlusCb = addMod(da, cb)
            let daMinusCb = subtractMod(da, cb)

            x3 = multiplyMod(daPlusCb, daPlusCb)
            z3 = multiplyMod(x1, multiplyMod(daMinusCb, daMinusCb))
            x2 = multiplyMod(aa, bb)
            z2 = multiplyMod(e, addMod(aa, multiplyMod(Self.a24, e)))
        }

        if swapState != 0 {
            exchange(&x2, &x3)
            exchange(&z2, &z3)
        }

        let zInverse = z2.power(Self.fieldPrime - Self.two, modulus: Self.fieldPrime)
        return toLittleEndian(multiplyMod(x2, zInverse), length: Self.keyLength)
    }

    private func scalarBit(_ scalar: [UInt8], bitIndex: Int) -> Int {
        let byteIndex = bitIndex / 8
        let bitOffset = bitIndex % 8
        return Int((scalar[byteIndex] >> bitOffset) & 0x01)
    }

    private func addMod(_ lhs: BigUInt, _ rhs: BigUInt) -> BigUInt {
        (lhs + rhs) % Self.fieldPrime
    }

    private func subtractMod(_ lhs: BigUInt, _ rhs: BigUInt) -> BigUInt {
        if lhs >= rhs {
            return lhs - rhs
        }
        return Self.fieldPrime - (rhs - lhs)
    }

    private func multiplyMod(_ lhs: BigUInt, _ rhs: BigUInt) -> BigUInt {
        (lhs * rhs) % Self.fieldPrime
    }

    private func exchange<T>(_ lhs: inout T, _ rhs: inout T) {
        let temporary = lhs
        lhs = rhs
        rhs = temporary
    }

    private func fromLittleEndian(_ bytes: Data) -> BigUInt {
        var value = BigUInt(0)
        for byte in bytes.reversed() {
            value <<= 8
            value |= BigUInt(byte)
        }
        return value
    }

    private func toLittleEndian(_ value: BigUInt, length: Int) -> Data {
        var remaining = value
        var bytes = [UInt8](repeating: 0, count: length)

        for index in 0..<length {
            bytes[index] = UInt8(truncatingIfNeeded: remaining)
            remaining >>= 8
        }

        return Data(bytes)
    }
}