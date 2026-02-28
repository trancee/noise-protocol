package dev.noiseprotocol.testing

import dev.noiseprotocol.core.HandshakePattern
import dev.noiseprotocol.crypto.CryptoProvider

data class HandshakeVector(
    val protocolName: String,
    val payloads: List<ByteArray>
)

class NoiseTestHarness(
    private val provider: CryptoProvider
) {
    fun canExecute(vector: HandshakeVector): Boolean {
        return vector.protocolName == HandshakePattern.XX.protocolName &&
            provider.supports(HandshakePattern.XX)
    }
}
