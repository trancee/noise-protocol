package com.noise.protocol.crypto

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.KeyAgreement
import java.math.BigInteger

/** Length in bytes of public keys and DH output. */
const val DHLEN = 32

/**
 * X25519 Diffie-Hellman key pair for Noise protocol.
 */
class NoiseKeyPair private constructor(
    private val javaKeyPair: KeyPair
) {
    val publicKey: ByteArray by lazy {
        val pub = javaKeyPair.public as java.security.interfaces.XECPublicKey
        val u = pub.u
        val bytes = u.toByteArray()
        val result = ByteArray(DHLEN)
        for (i in bytes.indices) {
            if (i < DHLEN) {
                result[i] = bytes[bytes.size - 1 - i]
            }
        }
        result
    }

    /** Perform X25519 Diffie-Hellman. Returns DHLEN (32) bytes. */
    fun dh(remotePublicKey: ByteArray): ByteArray {
        val remotePub = publicKeyFromBytes(remotePublicKey)
        val agreement = keyAgreementLocal.get()
        agreement.init(javaKeyPair.private)
        agreement.doPhase(remotePub, true)
        val secret = agreement.generateSecret()
        val result = ByteArray(DHLEN)
        System.arraycopy(secret, 0, result, 0, minOf(secret.size, DHLEN))
        return result
    }

    companion object {
        private val keyPairGenLocal = ThreadLocal.withInitial {
            KeyPairGenerator.getInstance("XDH").apply {
                initialize(NamedParameterSpec.X25519)
            }
        }
        private val keyFactoryLocal = ThreadLocal.withInitial {
            KeyFactory.getInstance("XDH")
        }
        private val keyAgreementLocal = ThreadLocal.withInitial {
            KeyAgreement.getInstance("XDH")
        }

        /** Generate a random X25519 key pair. */
        fun generate(): NoiseKeyPair {
            return NoiseKeyPair(keyPairGenLocal.get().generateKeyPair())
        }

        /** Create from a 32-byte private key (for deterministic testing). */
        fun fromPrivateKey(privateKeyData: ByteArray): NoiseKeyPair {
            require(privateKeyData.size == DHLEN) { "Private key must be $DHLEN bytes" }
            val kf = keyFactoryLocal.get()
            val privKey = kf.generatePrivate(
                XECPrivateKeySpec(NamedParameterSpec.X25519, privateKeyData)
            ) as java.security.interfaces.XECPrivateKey

            val pubBytes = computeX25519PublicKey(privateKeyData)
            val pubU = bytesToBigIntegerLE(pubBytes)
            val pubKeySpec = XECPublicKeySpec(NamedParameterSpec.X25519, pubU)
            val publicKey = kf.generatePublic(pubKeySpec)

            return NoiseKeyPair(KeyPair(publicKey, privKey))
        }

        /** Convert little-endian bytes to a PublicKey. */
        internal fun publicKeyFromBytes(bytes: ByteArray): PublicKey {
            require(bytes.size == DHLEN) { "Public key must be $DHLEN bytes" }
            val u = bytesToBigIntegerLE(bytes)
            val spec = XECPublicKeySpec(NamedParameterSpec.X25519, u)
            return keyFactoryLocal.get().generatePublic(spec)
        }

        /** Convert little-endian byte array to unsigned BigInteger. */
        private fun bytesToBigIntegerLE(bytes: ByteArray): BigInteger {
            // Reverse to big-endian, prepend 0 to ensure positive
            val reversed = ByteArray(bytes.size + 1)
            reversed[0] = 0
            for (i in bytes.indices) {
                reversed[bytes.size - i] = bytes[i]
            }
            return BigInteger(reversed)
        }

        /** Compute X25519 public key from private key bytes using JCA. */
        private fun computeX25519PublicKey(privateKeyData: ByteArray): ByteArray {
            val kf = keyFactoryLocal.get()
            val privKeySpec = XECPrivateKeySpec(NamedParameterSpec.X25519, privateKeyData)
            val privKey = kf.generatePrivate(privKeySpec)

            // X25519 basepoint is u=9
            val basepoint = ByteArray(DHLEN).also { it[0] = 9 }
            val basepointU = bytesToBigIntegerLE(basepoint)
            val basepointPubSpec = XECPublicKeySpec(NamedParameterSpec.X25519, basepointU)
            val basepointPub = kf.generatePublic(basepointPubSpec)

            val agreement = keyAgreementLocal.get()
            agreement.init(privKey)
            agreement.doPhase(basepointPub, true)
            val pubKey = agreement.generateSecret()
            val result = ByteArray(DHLEN)
            System.arraycopy(pubKey, 0, result, 0, minOf(pubKey.size, DHLEN))
            return result
        }
    }
}

/** Protocol for key pair generation, allowing deterministic injection for testing. */
interface NoiseKeyPairGenerator {
    fun generate(): NoiseKeyPair
}

/** Generates random X25519 key pairs. */
class RandomKeyPairGenerator : NoiseKeyPairGenerator {
    override fun generate(): NoiseKeyPair = NoiseKeyPair.generate()
}

/** Generates a key pair from a fixed private key (for test vectors). */
class DeterministicKeyPairGenerator(
    private val privateKeyData: ByteArray
) : NoiseKeyPairGenerator {
    override fun generate(): NoiseKeyPair = NoiseKeyPair.fromPrivateKey(privateKeyData)
}
