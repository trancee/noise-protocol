import Foundation

/// Result of a completed handshake: two CipherStates for transport encryption.
public struct TransportState: Sendable {
    /// Encrypts initiator→responder messages.
    public let sendCipher: CipherState
    /// Decrypts responder→initiator messages.
    public let receiveCipher: CipherState
    /// Handshake hash for channel binding.
    public let handshakeHash: Data
    /// Remote party's static public key (if authenticated during handshake).
    public let remoteStaticKey: Data?
}

/// Top-level Noise handshake state machine.
/// Processes handshake messages according to a pattern, then produces transport CipherStates.
public final class HandshakeState: @unchecked Sendable {
    private let suite: CipherSuite
    private let symmetricState: SymmetricState
    private var s: NoiseKeyPair?
    private var e: NoiseKeyPair?
    private var rs: Data?
    private var re: Data?
    private let initiator: Bool
    private var messagePatterns: [MessagePattern]
    private var messageIndex: Int = 0
    private let keyPairGenerator: KeyPairGenerator
    private var psks: [Data]
    private var pskIndex: Int = 0
    private var isComplete: Bool = false

    /// Initialize a Noise handshake.
    ///
    /// - Parameters:
    ///   - pattern: The handshake pattern to use.
    ///   - initiator: True if this party initiates the handshake.
    ///   - suite: The cipher suite to use. Defaults to 25519_ChaChaPoly_SHA256.
    ///   - prologue: Application-specific prologue data hashed into the handshake.
    ///   - s: Local static key pair (required for patterns that send/use a static key).
    ///   - e: Local ephemeral key pair (normally nil; set for testing with deterministic keys).
    ///   - rs: Remote static public key (required for K-type responder patterns).
    ///   - re: Remote ephemeral public key (required for fallback patterns).
    ///   - psks: Pre-shared keys for PSK-mode patterns.
    ///   - keyPairGenerator: Generator for ephemeral keys (override for deterministic testing).
    public init(
        pattern: HandshakePattern,
        initiator: Bool,
        suite: CipherSuite = .noise_25519_ChaChaPoly_SHA256,
        prologue: Data = Data(),
        s: NoiseKeyPair? = nil,
        e: NoiseKeyPair? = nil,
        rs: Data? = nil,
        re: Data? = nil,
        psks: [Data] = [],
        keyPairGenerator: KeyPairGenerator = RandomKeyPairGenerator()
    ) {
        self.suite = suite
        self.symmetricState = SymmetricState(suite: suite)
        self.initiator = initiator
        self.s = s
        self.e = e
        self.rs = rs
        self.re = re
        self.messagePatterns = pattern.messagePatterns
        self.keyPairGenerator = keyPairGenerator
        self.psks = psks
        self.pskIndex = 0

        // Check if pattern uses PSK
        let hasPSK = pattern.messagePatterns.contains { $0.contains(.psk) }
        symmetricState.hasPSK = hasPSK

        // Construct protocol name
        let protocolName = suite.protocolName(pattern: pattern.name)

        symmetricState.initializeSymmetric(protocolName: protocolName)
        symmetricState.mixHash(prologue)

        // Process pre-messages
        for token in pattern.initiatorPreMessage {
            if token == .s {
                if initiator {
                    if let s = s { symmetricState.mixHash(s.publicKey) }
                } else {
                    if let rs = rs { symmetricState.mixHash(rs) }
                }
            } else if token == .e {
                if initiator {
                    if let e = e { symmetricState.mixHash(e.publicKey) }
                } else {
                    if let re = re { symmetricState.mixHash(re) }
                }
            }
        }
        for token in pattern.responderPreMessage {
            if token == .s {
                if !initiator {
                    if let s = s { symmetricState.mixHash(s.publicKey) }
                } else {
                    if let rs = rs { symmetricState.mixHash(rs) }
                }
            } else if token == .e {
                if !initiator {
                    if let e = e { symmetricState.mixHash(e.publicKey) }
                } else {
                    if let re = re { symmetricState.mixHash(re) }
                }
            }
        }
    }

    /// True if it's this party's turn to write (send) a message.
    public var isMySend: Bool {
        let senderIsInitiator = (messageIndex % 2 == 0)
        return senderIsInitiator == initiator
    }

    /// Write a handshake message with optional payload.
    /// Returns the message bytes. If the handshake is now complete, also returns a TransportState.
    public func writeMessage(payload: Data = Data()) throws -> (Data, TransportState?) {
        guard !isComplete else { throw NoiseError.handshakeAlreadyComplete }
        guard messageIndex < messagePatterns.count else { throw NoiseError.handshakeAlreadyComplete }
        guard isMySend else { throw NoiseError.notYourTurn }

        let pattern = messagePatterns[messageIndex]
        messageIndex += 1
        var buffer = Data(capacity: 256)

        for token in pattern {
            switch token {
            case .e:
                if e == nil {
                    e = keyPairGenerator.generate()
                }
                buffer.append(e!.publicKey)
                symmetricState.mixHash(e!.publicKey)
                if symmetricState.hasPSK {
                    symmetricState.mixKey(e!.publicKey)
                }

            case .s:
                let encrypted = try symmetricState.encryptAndHash(s!.publicKey)
                buffer.append(encrypted)

            case .ee:
                symmetricState.mixKey(try e!.dh(remotePublicKey: re!))

            case .es:
                if initiator {
                    symmetricState.mixKey(try e!.dh(remotePublicKey: rs!))
                } else {
                    symmetricState.mixKey(try s!.dh(remotePublicKey: re!))
                }

            case .se:
                if initiator {
                    symmetricState.mixKey(try s!.dh(remotePublicKey: re!))
                } else {
                    symmetricState.mixKey(try e!.dh(remotePublicKey: rs!))
                }

            case .ss:
                symmetricState.mixKey(try s!.dh(remotePublicKey: rs!))

            case .psk:
                guard pskIndex < psks.count else { throw NoiseError.missingKey("PSK at index \(pskIndex)") }
                symmetricState.mixKeyAndHash(psks[pskIndex])
                pskIndex += 1
            }
        }

        let encryptedPayload = try symmetricState.encryptAndHash(payload)
        buffer.append(encryptedPayload)

        if messageIndex >= messagePatterns.count {
            return (buffer, finalize())
        }
        return (buffer, nil)
    }

    /// Read a handshake message from the remote party.
    /// Returns the decrypted payload. If the handshake is now complete, also returns a TransportState.
    public func readMessage(_ message: Data) throws -> (Data, TransportState?) {
        guard !isComplete else { throw NoiseError.handshakeAlreadyComplete }
        guard messageIndex < messagePatterns.count else { throw NoiseError.handshakeAlreadyComplete }
        guard !isMySend else { throw NoiseError.notYourTurn }

        let pattern = messagePatterns[messageIndex]
        messageIndex += 1
        var offset = 0
        let dhlen = suite.dhlen

        for token in pattern {
            switch token {
            case .e:
                guard message.count >= offset + dhlen else { throw NoiseError.invalidMessage }
                re = Data(message[offset..<(offset + dhlen)])
                offset += dhlen
                symmetricState.mixHash(re!)
                if symmetricState.hasPSK {
                    symmetricState.mixKey(re!)
                }

            case .s:
                let len = symmetricState.hasKey ? dhlen + 16 : dhlen
                guard message.count >= offset + len else { throw NoiseError.invalidMessage }
                let temp = Data(message[offset..<(offset + len)])
                offset += len
                rs = try symmetricState.decryptAndHash(temp)

            case .ee:
                symmetricState.mixKey(try e!.dh(remotePublicKey: re!))

            case .es:
                if initiator {
                    symmetricState.mixKey(try e!.dh(remotePublicKey: rs!))
                } else {
                    symmetricState.mixKey(try s!.dh(remotePublicKey: re!))
                }

            case .se:
                if initiator {
                    symmetricState.mixKey(try s!.dh(remotePublicKey: re!))
                } else {
                    symmetricState.mixKey(try e!.dh(remotePublicKey: rs!))
                }

            case .ss:
                symmetricState.mixKey(try s!.dh(remotePublicKey: rs!))

            case .psk:
                guard pskIndex < psks.count else { throw NoiseError.missingKey("PSK at index \(pskIndex)") }
                symmetricState.mixKeyAndHash(psks[pskIndex])
                pskIndex += 1
            }
        }

        let remaining = Data(message[offset...])
        let payload = try symmetricState.decryptAndHash(remaining)

        if messageIndex >= messagePatterns.count {
            return (payload, finalize())
        }
        return (payload, nil)
    }

    private func finalize() -> TransportState {
        isComplete = true
        let (c1, c2) = symmetricState.split()
        let handshakeHash = symmetricState.getHandshakeHash()
        if initiator {
            return TransportState(
                sendCipher: c1,
                receiveCipher: c2,
                handshakeHash: handshakeHash,
                remoteStaticKey: rs
            )
        } else {
            return TransportState(
                sendCipher: c2,
                receiveCipher: c1,
                handshakeHash: handshakeHash,
                remoteStaticKey: rs
            )
        }
    }

    /// The remote party's static public key, if received during the handshake.
    public var remoteStaticPublicKey: Data? { rs }
}
