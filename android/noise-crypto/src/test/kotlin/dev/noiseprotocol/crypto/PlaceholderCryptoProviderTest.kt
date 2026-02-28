package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.HandshakePattern
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PlaceholderCryptoProviderTest {
    @Test
    fun supportsXxPattern() {
        val provider = PlaceholderCryptoProvider()
        assertTrue(provider.supports(HandshakePattern.XX))
    }
}
