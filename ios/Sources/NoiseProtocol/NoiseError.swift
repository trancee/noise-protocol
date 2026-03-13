import Foundation

/// Errors that can occur during Noise protocol operations.
public enum NoiseError: Error, Sendable {
    case nonceExhausted
    case noKey
    case decryptionFailed
    case invalidPublicKey
    case handshakeNotComplete
    case handshakeAlreadyComplete
    case invalidMessage
    case invalidPayloadSize
    case unknownPattern(String)
    case missingKey(String)
    case notYourTurn
}
