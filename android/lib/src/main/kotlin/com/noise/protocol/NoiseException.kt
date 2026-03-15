package com.noise.protocol

sealed class NoiseException(message: String) : Exception(message) {
    class NonceExhausted : NoiseException("Nonce exhausted — maximum message count reached")
    class NoKey : NoiseException("No cipher key has been set")
    class DecryptionFailed : NoiseException("AEAD authentication failed")
    class InvalidPublicKey : NoiseException("Invalid public key")
    class HandshakeNotComplete : NoiseException("Handshake has not completed yet")
    class HandshakeAlreadyComplete : NoiseException("Handshake has already completed")
    class InvalidMessage : NoiseException("Handshake message is malformed or truncated")
    class InvalidPayloadSize : NoiseException("Payload exceeds maximum size (65535 bytes)")
    class UnknownPattern(name: String) : NoiseException("Unknown handshake pattern: $name")
    class MissingKey(detail: String) : NoiseException("Missing key: $detail")
    class NotYourTurn : NoiseException("It is not your turn to send or receive")
}
