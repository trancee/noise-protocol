package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.NoiseHashFunction
import dev.noiseprotocol.core.NoiseKeyDerivationFunction
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

abstract class MessageDigestHashAdapter(
    private val algorithm: String,
    final override val hashLength: Int
) : NoiseHashFunction {
    override fun hash(data: ByteArray): ByteArray {
        return MessageDigest.getInstance(algorithm).digest(data)
    }
}

class Sha256HashAdapter : MessageDigestHashAdapter(
    algorithm = "SHA-256",
    hashLength = 32
)

class Sha512HashAdapter : MessageDigestHashAdapter(
    algorithm = "SHA-512",
    hashLength = 64
)

abstract class HmacHkdfAdapter(
    private val hmacAlgorithm: String,
    private val outputLength: Int
) : NoiseKeyDerivationFunction {
    override fun hkdf(chainingKey: ByteArray, inputKeyMaterial: ByteArray, outputs: Int): List<ByteArray> {
        require(outputs in 1..255) { "HKDF output count must be between 1 and 255." }

        val pseudorandomKey = hmac(chainingKey, inputKeyMaterial)
        val result = ArrayList<ByteArray>(outputs)
        var previous = ByteArray(0)

        for (counter in 1..outputs) {
            previous = hmac(pseudorandomKey, previous + counter.toByte())
            result += previous.copyOf(outputLength)
        }
        return result
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(hmacAlgorithm)
        mac.init(SecretKeySpec(key.copyOf(), hmacAlgorithm))
        return mac.doFinal(data)
    }
}

class HkdfSha256Adapter : HmacHkdfAdapter(
    hmacAlgorithm = "HmacSHA256",
    outputLength = 32
)

class HkdfSha512Adapter : HmacHkdfAdapter(
    hmacAlgorithm = "HmacSHA512",
    outputLength = 64
)
