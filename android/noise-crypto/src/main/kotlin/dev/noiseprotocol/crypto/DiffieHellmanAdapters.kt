package noise.protocol.crypto

import noise.protocol.core.NoiseDiffieHellmanFunction
import noise.protocol.core.NoiseKeyPair
import java.math.BigInteger
import java.security.SecureRandom

interface NoiseDhAdapter : NoiseDiffieHellmanFunction {
    val privateKeyLength: Int
    val publicKeyLength: Int
}

private val BIG_TWO: BigInteger = BigInteger.valueOf(2)

class X25519DiffieHellmanAdapter : MontgomeryCurveDiffieHellmanAdapter(
    privateKeyLength = 32,
    publicKeyLength = 32,
    scalarBits = 255,
    fieldPrime = BIG_TWO.pow(255) - BigInteger.valueOf(19),
    a24 = BigInteger.valueOf(121665),
    basePoint = byteArrayOf(9)
) {
    override fun clampScalar(privateKey: ByteArray) {
        privateKey[0] = (privateKey[0].toInt() and 0xF8).toByte()
        privateKey[31] = ((privateKey[31].toInt() and 0x7F) or 0x40).toByte()
    }

    override fun maskInputCoordinate(coordinate: ByteArray) {
        coordinate[31] = (coordinate[31].toInt() and 0x7F).toByte()
    }
}

class X448DiffieHellmanAdapter : MontgomeryCurveDiffieHellmanAdapter(
    privateKeyLength = 56,
    publicKeyLength = 56,
    scalarBits = 448,
    fieldPrime = BIG_TWO.pow(448) - BIG_TWO.pow(224) - BigInteger.ONE,
    a24 = BigInteger.valueOf(39081),
    basePoint = byteArrayOf(5)
) {
    override fun clampScalar(privateKey: ByteArray) {
        privateKey[0] = (privateKey[0].toInt() and 0xFC).toByte()
        privateKey[55] = (privateKey[55].toInt() or 0x80).toByte()
    }
}

abstract class MontgomeryCurveDiffieHellmanAdapter(
    final override val privateKeyLength: Int,
    final override val publicKeyLength: Int,
    private val scalarBits: Int,
    private val fieldPrime: BigInteger,
    private val a24: BigInteger,
    basePoint: ByteArray
) : NoiseDhAdapter {
    private val basePointCoordinate = fromLittleEndian(basePoint)

    final override fun generateKeyPair(): NoiseKeyPair {
        val privateKey = ByteArray(privateKeyLength)
        RANDOM.nextBytes(privateKey)
        clampScalar(privateKey)
        val publicKey = scalarMultiply(privateKey, basePointCoordinate)
        return NoiseKeyPair(
            privateKey = privateKey.copyOf(),
            publicKey = publicKey
        )
    }

    final override fun dh(localPrivateKey: ByteArray, remotePublicKey: ByteArray): ByteArray {
        require(localPrivateKey.size == privateKeyLength) {
            "Private key must be $privateKeyLength bytes."
        }
        require(remotePublicKey.size == publicKeyLength) {
            "Public key must be $publicKeyLength bytes."
        }

        val scalar = localPrivateKey.copyOf()
        clampScalar(scalar)
        val uCoordinateBytes = remotePublicKey.copyOf()
        maskInputCoordinate(uCoordinateBytes)
        val uCoordinate = fromLittleEndian(uCoordinateBytes).mod(fieldPrime)
        return scalarMultiply(scalar, uCoordinate)
    }

    protected open fun maskInputCoordinate(coordinate: ByteArray) {
        // No-op for curves without coordinate masking requirements.
    }

    protected abstract fun clampScalar(privateKey: ByteArray)

    private fun scalarMultiply(scalar: ByteArray, uCoordinate: BigInteger): ByteArray {
        var x1 = uCoordinate.mod(fieldPrime)
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0

        for (bitIndex in scalarBits - 1 downTo 0) {
            val currentBit = scalarBit(scalar, bitIndex)
            if (swap != currentBit) {
                val tmpX = x2
                x2 = x3
                x3 = tmpX
                val tmpZ = z2
                z2 = z3
                z3 = tmpZ
            }
            swap = currentBit

            val a = mod(x2 + z2)
            val aa = mod(a * a)
            val b = mod(x2 - z2)
            val bb = mod(b * b)
            val e = mod(aa - bb)
            val c = mod(x3 + z3)
            val d = mod(x3 - z3)
            val da = mod(d * a)
            val cb = mod(c * b)
            val daPlusCb = mod(da + cb)
            val daMinusCb = mod(da - cb)

            x3 = mod(daPlusCb * daPlusCb)
            z3 = mod(x1 * daMinusCb * daMinusCb)
            x2 = mod(aa * bb)
            z2 = mod(e * mod(aa + a24 * e))
        }

        if (swap != 0) {
            val tmpX = x2
            x2 = x3
            x3 = tmpX
            val tmpZ = z2
            z2 = z3
            z3 = tmpZ
        }

        // For invalid inputs this naturally maps to zero output, matching RFC behavior.
        val zInverse = z2.modPow(fieldPrime - TWO, fieldPrime)
        return toLittleEndian(mod(x2 * zInverse), publicKeyLength)
    }

    private fun scalarBit(scalar: ByteArray, bitIndex: Int): Int {
        val byteIndex = bitIndex / 8
        val bitOffset = bitIndex % 8
        return (scalar[byteIndex].toInt() ushr bitOffset) and 0x01
    }

    private fun mod(value: BigInteger): BigInteger {
        val reduced = value.mod(fieldPrime)
        return if (reduced.signum() < 0) reduced + fieldPrime else reduced
    }

    private companion object {
        val TWO: BigInteger = BigInteger.valueOf(2)
        val RANDOM = SecureRandom()
    }
}

private fun fromLittleEndian(value: ByteArray): BigInteger = BigInteger(1, value.reversedArray())

private fun toLittleEndian(value: BigInteger, length: Int): ByteArray {
    val normalized = value.toByteArray().let { bytes ->
        when {
            bytes.size == length -> bytes
            bytes.size < length -> ByteArray(length - bytes.size) + bytes
            bytes.size == length + 1 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, bytes.size)
            else -> bytes.copyOfRange(bytes.size - length, bytes.size)
        }
    }

    val littleEndian = ByteArray(length)
    for (index in normalized.indices) {
        littleEndian[index] = normalized[normalized.lastIndex - index]
    }
    return littleEndian
}
