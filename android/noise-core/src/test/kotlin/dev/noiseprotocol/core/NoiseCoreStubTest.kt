package dev.noiseprotocol.core

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NoiseCoreStubTest {
    @Test
    fun exposesXxPattern() {
        assertTrue(NoiseCoreStub.supportedPatterns().contains(HandshakePattern.XX))
    }
}
