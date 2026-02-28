package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.NoiseDiffieHellmanFunction
import dev.noiseprotocol.core.NoiseKeyPair
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement

interface NoiseDhAdapter : NoiseDiffieHellmanFunction {
    val privateKeyLength: Int
    val publicKeyLength: Int
}

class X25519DiffieHellmanAdapter : NoiseDhAdapter {
    override val privateKeyLength: Int = 32
    override val publicKeyLength: Int = 32

    override fun generateKeyPair(): NoiseKeyPair {
        val keyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        val privateKey = keyPair.private as XECPrivateKey
        val publicKey = keyPair.public as XECPublicKey
        val scalar = privateKey.scalar.orElseThrow {
            IllegalStateException("Unable to extract X25519 private key bytes.")
        }

        return NoiseKeyPair(
            privateKey = normalizeLength(scalar, privateKeyLength),
            publicKey = toLittleEndian(publicKey.u, publicKeyLength)
        )
    }

    override fun dh(localPrivateKey: ByteArray, remotePublicKey: ByteArray): ByteArray {
        require(localPrivateKey.size == privateKeyLength) { "X25519 private key must be 32 bytes." }
        require(remotePublicKey.size == publicKeyLength) { "X25519 public key must be 32 bytes." }

        val keyFactory = KeyFactory.getInstance("XDH")
        val privateKey = keyFactory.generatePrivate(
            XECPrivateKeySpec(NamedParameterSpec.X25519, localPrivateKey.copyOf())
        )
        val publicKey = keyFactory.generatePublic(
            XECPublicKeySpec(NamedParameterSpec.X25519, fromLittleEndian(remotePublicKey))
        )

        val agreement = KeyAgreement.getInstance("X25519")
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)

        return normalizeLength(agreement.generateSecret(), publicKeyLength)
    }
}

private fun normalizeLength(value: ByteArray, expectedLength: Int): ByteArray {
    require(value.size <= expectedLength) { "Value length ${value.size} exceeds expected length $expectedLength." }
    return value.copyOf(expectedLength)
}

private fun toLittleEndian(value: BigInteger, length: Int): ByteArray {
    val bigEndian = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
    require(bigEndian.size <= length) { "Public key is longer than expected." }

    val littleEndian = ByteArray(length)
    for (index in bigEndian.indices) {
        littleEndian[index] = bigEndian[bigEndian.lastIndex - index]
    }
    return littleEndian
}

private fun fromLittleEndian(value: ByteArray): BigInteger {
    return BigInteger(1, value.reversedArray())
}
