package dev.noiseprotocol.core

enum class HandshakePattern(val protocolName: String) {
    XX("Noise_XX")
}

object NoiseCoreStub {
    fun supportedPatterns(): Set<HandshakePattern> = setOf(HandshakePattern.XX)
}
