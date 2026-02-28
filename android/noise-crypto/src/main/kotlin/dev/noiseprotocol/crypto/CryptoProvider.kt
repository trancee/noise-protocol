package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.HandshakePattern

interface CryptoProvider {
    val id: String

    fun supports(pattern: HandshakePattern): Boolean
}

class PlaceholderCryptoProvider(
    override val id: String = "placeholder"
) : CryptoProvider {
    override fun supports(pattern: HandshakePattern): Boolean = pattern == HandshakePattern.XX
}
