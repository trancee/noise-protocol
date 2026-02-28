package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.HandshakePattern
import dev.noiseprotocol.core.NoiseCipherFunction
import dev.noiseprotocol.core.NoiseCryptoSuite
import dev.noiseprotocol.core.NoiseDiffieHellmanFunction
import dev.noiseprotocol.core.NoiseHashFunction
import dev.noiseprotocol.core.NoiseKeyDerivationFunction

interface NoiseProvider {
    val id: String

    fun supports(pattern: HandshakePattern): Boolean
}

interface NoiseCryptoSuiteProvider : NoiseProvider {
    fun createSuite(algorithms: NoiseCryptoAlgorithms = NoiseCryptoAlgorithms()): NoiseCryptoSuite
}

data class NoiseCryptoAlgorithms(
    val dh: NoiseDhAlgorithm = NoiseDhAlgorithm.X25519,
    val aead: NoiseAeadAlgorithm = NoiseAeadAlgorithm.CHACHA20_POLY1305,
    val hash: NoiseHashAlgorithm = NoiseHashAlgorithm.SHA256
)

enum class NoiseDhAlgorithm {
    X25519,
    X448
}

enum class NoiseAeadAlgorithm {
    CHACHA20_POLY1305,
    AES_GCM
}

enum class NoiseHashAlgorithm {
    SHA256,
    SHA512,
    BLAKE2S,
    BLAKE2B
}

open class CryptoProvider(
    override val id: String = "android-custom"
) : NoiseCryptoSuiteProvider {
    override fun supports(pattern: HandshakePattern): Boolean = true

    override fun createSuite(algorithms: NoiseCryptoAlgorithms): NoiseCryptoSuite {
        val hash = when (algorithms.hash) {
            NoiseHashAlgorithm.SHA256 -> Sha256HashAdapter()
            NoiseHashAlgorithm.SHA512 -> Sha512HashAdapter()
            NoiseHashAlgorithm.BLAKE2S -> Blake2sHashAdapter()
            NoiseHashAlgorithm.BLAKE2B -> Blake2bHashAdapter()
        }
        val hkdf = when (algorithms.hash) {
            NoiseHashAlgorithm.SHA256 -> HkdfSha256Adapter()
            NoiseHashAlgorithm.SHA512 -> HkdfSha512Adapter()
            NoiseHashAlgorithm.BLAKE2S -> HkdfBlake2sAdapter()
            NoiseHashAlgorithm.BLAKE2B -> HkdfBlake2bAdapter()
        }
        val cipher = when (algorithms.aead) {
            NoiseAeadAlgorithm.CHACHA20_POLY1305 -> ChaCha20Poly1305CipherAdapter()
            NoiseAeadAlgorithm.AES_GCM -> AesGcmCipherAdapter()
        }
        val diffieHellman = when (algorithms.dh) {
            NoiseDhAlgorithm.X25519 -> X25519DiffieHellmanAdapter()
            NoiseDhAlgorithm.X448 -> X448DiffieHellmanAdapter()
        }

        return DefaultNoiseCryptoSuite(
            hash = hash,
            keyDerivation = hkdf,
            cipher = cipher,
            diffieHellman = diffieHellman
        )
    }

}

data class DefaultNoiseCryptoSuite(
    override val hash: NoiseHashFunction,
    override val keyDerivation: NoiseKeyDerivationFunction,
    override val cipher: NoiseCipherFunction,
    override val diffieHellman: NoiseDiffieHellmanFunction
) : NoiseCryptoSuite

@Deprecated("Use CryptoProvider.")
typealias PlaceholderCryptoProvider = CryptoProvider
