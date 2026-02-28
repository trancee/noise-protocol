package dev.noiseprotocol.testing

import dev.noiseprotocol.core.HandshakePattern
import dev.noiseprotocol.crypto.PlaceholderCryptoProvider
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NoiseTestHarnessTest {
    @Test
    fun acceptsXxVectorForPlaceholderProvider() {
        val harness = NoiseTestHarness(PlaceholderCryptoProvider())
        val vector = HandshakeVector(
            protocolName = HandshakePattern.XX.protocolName,
            payloads = emptyList()
        )

        assertTrue(harness.canExecute(vector))
    }
}
