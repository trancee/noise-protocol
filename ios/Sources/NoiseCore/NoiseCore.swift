import Foundation

public enum NoiseCoreVersion: Sendable {
    public static let specificationRevision = 34
}

public struct NoiseProtocolDescriptor: Sendable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static let bootstrapDefault = NoiseProtocolDescriptor(
        rawValue: "Noise_XX_25519_ChaChaPoly_BLAKE2s"
    )
}

public enum NoiseHandshakePatternName: String, Sendable, CaseIterable {
    case nn = "NN"
    case nk = "NK"
    case kk = "KK"
    case ik = "IK"
    case xx = "XX"

    public init?(protocolDescriptor: NoiseProtocolDescriptor) {
        let parts = protocolDescriptor.rawValue.split(separator: "_")
        guard parts.count >= 2 else {
            return nil
        }
        self.init(rawValue: String(parts[1]))
    }
}

public enum NoiseMessageDirection: Sendable, Equatable {
    case initiatorToResponder
    case responderToInitiator

    public var inverted: NoiseMessageDirection {
        switch self {
        case .initiatorToResponder:
            return .responderToInitiator
        case .responderToInitiator:
            return .initiatorToResponder
        }
    }
}

public enum NoisePatternToken: String, Sendable, Equatable, CaseIterable {
    case e
    case s
    case ee
    case es
    case se
    case ss
}

public struct NoisePatternMessage: Sendable, Equatable {
    public let direction: NoiseMessageDirection
    public let tokens: [NoisePatternToken]

    public init(direction: NoiseMessageDirection, tokens: [NoisePatternToken]) {
        self.direction = direction
        self.tokens = tokens
    }
}

public struct NoiseHandshakePatternDefinition: Sendable, Equatable {
    public let name: NoiseHandshakePatternName
    public let preMessages: [NoisePatternMessage]
    public let messages: [NoisePatternMessage]

    public init(
        name: NoiseHandshakePatternName,
        preMessages: [NoisePatternMessage],
        messages: [NoisePatternMessage]
    ) {
        self.name = name
        self.preMessages = preMessages
        self.messages = messages
    }
}

public enum NoiseHandshakePatterns {
    public static let nn = NoiseHandshakePatternDefinition(
        name: .nn,
        preMessages: [],
        messages: [
            NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e]),
            NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee]),
        ]
    )

    public static let nk = NoiseHandshakePatternDefinition(
        name: .nk,
        preMessages: [
            NoisePatternMessage(direction: .responderToInitiator, tokens: [.s]),
        ],
        messages: [
            NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es]),
            NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee]),
        ]
    )

    public static let kk = NoiseHandshakePatternDefinition(
        name: .kk,
        preMessages: [
            NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s]),
            NoisePatternMessage(direction: .responderToInitiator, tokens: [.s]),
        ],
        messages: [
            NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es, .ss]),
            NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se]),
        ]
    )

    public static let ik = NoiseHandshakePatternDefinition(
        name: .ik,
        preMessages: [
            NoisePatternMessage(direction: .responderToInitiator, tokens: [.s]),
        ],
        messages: [
            NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es, .s, .ss]),
            NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se]),
        ]
    )

    public static let xx = NoiseHandshakePatternDefinition(
        name: .xx,
        preMessages: [],
        messages: [
            NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e]),
            NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .s, .es]),
            NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s, .se]),
        ]
    )

    public static let all: [NoiseHandshakePatternDefinition] = [nn, nk, kk, ik, xx]

    public static func pattern(named name: NoiseHandshakePatternName) -> NoiseHandshakePatternDefinition {
        switch name {
        case .nn:
            return nn
        case .nk:
            return nk
        case .kk:
            return kk
        case .ik:
            return ik
        case .xx:
            return xx
        }
    }
}

public struct NoiseDHKeyPair: Sendable, Equatable {
    public let privateKey: Data
    public let publicKey: Data

    public init(privateKey: Data, publicKey: Data) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

public protocol NoiseDiffieHellmanAlgorithm: Sendable {
    func generateKeyPair() throws -> NoiseDHKeyPair
    func dh(privateKey: Data, publicKey: Data) throws -> Data
}

public protocol NoiseCipherAlgorithm: Sendable {
    func encrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        plaintext: Data
    ) throws -> Data

    func decrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        ciphertext: Data
    ) throws -> Data

    func rekey(_ key: Data) throws -> Data
}

public protocol NoiseHashAlgorithm: Sendable {
    var hashLength: Int { get }
    func hash(_ data: Data) -> Data
    func hkdf(chainingKey: Data, inputKeyMaterial: Data, outputCount: Int) -> [Data]
}

public struct NoiseCryptoProvider: Sendable {
    public let diffieHellman: any NoiseDiffieHellmanAlgorithm
    public let cipher: any NoiseCipherAlgorithm
    public let hash: any NoiseHashAlgorithm

    public init(
        diffieHellman: any NoiseDiffieHellmanAlgorithm,
        cipher: any NoiseCipherAlgorithm,
        hash: any NoiseHashAlgorithm
    ) {
        self.diffieHellman = diffieHellman
        self.cipher = cipher
        self.hash = hash
    }
}

public enum NoiseCoreError: Error, Sendable, Equatable {
    case missingKeyMaterial(String)
    case nonceOverflow
    case invalidHKDFOutput(expected: Int, actual: Int)
    case unexpectedMessageDirection(expected: NoiseMessageDirection, actual: NoiseMessageDirection)
    case handshakeComplete
    case handshakeNotComplete
    case handshakeNotInitialized
    case invalidMessage(String)
}

public struct NoiseCipherState: Sendable, Equatable {
    public private(set) var key: Data?
    public private(set) var nonce: UInt64

    public init(key: Data? = nil, nonce: UInt64 = 0) {
        self.key = key
        self.nonce = nonce
    }

    public var hasKey: Bool {
        key != nil
    }

    public mutating func initializeKey(_ key: Data?) {
        self.key = key
        nonce = 0
    }

    public mutating func encryptWithAd(
        _ associatedData: Data,
        plaintext: Data,
        using cipher: any NoiseCipherAlgorithm
    ) throws -> Data {
        guard let key else {
            return plaintext
        }
        guard nonce < UInt64.max else {
            throw NoiseCoreError.nonceOverflow
        }

        let currentNonce = nonce
        nonce &+= 1
        return try cipher.encrypt(
            key: key,
            nonce: currentNonce,
            associatedData: associatedData,
            plaintext: plaintext
        )
    }

    public mutating func decryptWithAd(
        _ associatedData: Data,
        ciphertext: Data,
        using cipher: any NoiseCipherAlgorithm
    ) throws -> Data {
        guard let key else {
            return ciphertext
        }
        guard nonce < UInt64.max else {
            throw NoiseCoreError.nonceOverflow
        }

        let currentNonce = nonce
        nonce &+= 1
        return try cipher.decrypt(
            key: key,
            nonce: currentNonce,
            associatedData: associatedData,
            ciphertext: ciphertext
        )
    }

    public mutating func rekey(using cipher: any NoiseCipherAlgorithm) throws {
        guard let key else {
            return
        }
        self.key = try cipher.rekey(key)
    }
}

public struct NoiseTransportCipherStates: Sendable, Equatable {
    public let initiatorToResponder: NoiseCipherState
    public let responderToInitiator: NoiseCipherState

    public init(
        initiatorToResponder: NoiseCipherState,
        responderToInitiator: NoiseCipherState
    ) {
        self.initiatorToResponder = initiatorToResponder
        self.responderToInitiator = responderToInitiator
    }
}

public struct NoiseSymmetricState: Sendable, Equatable {
    public private(set) var chainingKey: Data
    public private(set) var handshakeHash: Data
    public private(set) var cipherState: NoiseCipherState

    public init(protocolName: NoiseProtocolDescriptor, hash: any NoiseHashAlgorithm) {
        let initialHash = hash.hash(Data(protocolName.rawValue.utf8))
        chainingKey = initialHash
        handshakeHash = initialHash
        cipherState = NoiseCipherState()
    }

    public mutating func mixHash(_ data: Data, hash: any NoiseHashAlgorithm) {
        var input = handshakeHash
        input.append(data)
        handshakeHash = hash.hash(input)
    }

    public mutating func mixKey(_ inputKeyMaterial: Data, hash: any NoiseHashAlgorithm) throws {
        let outputs = hash.hkdf(chainingKey: chainingKey, inputKeyMaterial: inputKeyMaterial, outputCount: 2)
        guard outputs.count == 2 else {
            throw NoiseCoreError.invalidHKDFOutput(expected: 2, actual: outputs.count)
        }
        chainingKey = outputs[0]
        cipherState.initializeKey(outputs[1])
    }

    public mutating func encryptAndHash(
        _ plaintext: Data,
        cipher: any NoiseCipherAlgorithm,
        hash: any NoiseHashAlgorithm
    ) throws -> Data {
        let ciphertext = try cipherState.encryptWithAd(handshakeHash, plaintext: plaintext, using: cipher)
        mixHash(ciphertext, hash: hash)
        return ciphertext
    }

    public mutating func decryptAndHash(
        _ ciphertext: Data,
        cipher: any NoiseCipherAlgorithm,
        hash: any NoiseHashAlgorithm
    ) throws -> Data {
        let plaintext = try cipherState.decryptWithAd(handshakeHash, ciphertext: ciphertext, using: cipher)
        mixHash(ciphertext, hash: hash)
        return plaintext
    }

    public func split(hash: any NoiseHashAlgorithm) throws -> NoiseTransportCipherStates {
        let outputs = hash.hkdf(chainingKey: chainingKey, inputKeyMaterial: Data(), outputCount: 2)
        guard outputs.count == 2 else {
            throw NoiseCoreError.invalidHKDFOutput(expected: 2, actual: outputs.count)
        }
        return NoiseTransportCipherStates(
            initiatorToResponder: NoiseCipherState(key: outputs[0], nonce: 0),
            responderToInitiator: NoiseCipherState(key: outputs[1], nonce: 0)
        )
    }
}

public struct NoiseHandshakeConfiguration: Sendable, Equatable {
    public var protocolName: NoiseProtocolDescriptor
    public var isInitiator: Bool
    public var handshakePattern: NoiseHandshakePatternName
    public var prologue: Data
    public var localStaticKey: NoiseDHKeyPair?
    public var localEphemeralKey: NoiseDHKeyPair?
    public var remoteStaticKey: Data?
    public var remoteEphemeralKey: Data?

    public init(
        protocolName: NoiseProtocolDescriptor = .bootstrapDefault,
        isInitiator: Bool,
        handshakePattern: NoiseHandshakePatternName? = nil,
        prologue: Data = Data(),
        localStaticKey: NoiseDHKeyPair? = nil,
        localEphemeralKey: NoiseDHKeyPair? = nil,
        remoteStaticKey: Data? = nil,
        remoteEphemeralKey: Data? = nil
    ) {
        self.protocolName = protocolName
        self.isInitiator = isInitiator
        self.handshakePattern = handshakePattern ?? NoiseHandshakePatternName(protocolDescriptor: protocolName) ?? .xx
        self.prologue = prologue
        self.localStaticKey = localStaticKey
        self.localEphemeralKey = localEphemeralKey
        self.remoteStaticKey = remoteStaticKey
        self.remoteEphemeralKey = remoteEphemeralKey
    }
}

public enum NoiseCoreBootstrapError: Error, Sendable, Equatable {
    case notImplemented(String)
}

public struct NoiseHandshakeMessage: Sendable, Equatable {
    public let keyPayloads: [Data]
    public let payload: Data

    public init(keyPayloads: [Data], payload: Data) {
        self.keyPayloads = keyPayloads
        self.payload = payload
    }

    public func encoded() throws -> Data {
        guard keyPayloads.count <= Int(UInt16.max) else {
            throw NoiseCoreError.invalidMessage("Too many key payloads.")
        }
        guard payload.count <= Int(UInt16.max) else {
            throw NoiseCoreError.invalidMessage("Payload too large.")
        }

        var output = Data()
        output.appendUInt16(UInt16(keyPayloads.count))
        for keyPayload in keyPayloads {
            guard keyPayload.count <= Int(UInt16.max) else {
                throw NoiseCoreError.invalidMessage("Key payload too large.")
            }
            output.appendUInt16(UInt16(keyPayload.count))
            output.append(keyPayload)
        }
        output.appendUInt16(UInt16(payload.count))
        output.append(payload)
        return output
    }

    public init(encoded data: Data) throws {
        var cursor = 0
        let keyPayloadCount = try Self.readUInt16(from: data, cursor: &cursor)

        var keyPayloads: [Data] = []
        keyPayloads.reserveCapacity(Int(keyPayloadCount))
        for _ in 0..<Int(keyPayloadCount) {
            let payloadLength = try Self.readUInt16(from: data, cursor: &cursor)
            let payload = try Self.readBytes(from: data, length: Int(payloadLength), cursor: &cursor)
            keyPayloads.append(payload)
        }

        let payloadLength = try Self.readUInt16(from: data, cursor: &cursor)
        let payload = try Self.readBytes(from: data, length: Int(payloadLength), cursor: &cursor)

        guard cursor == data.count else {
            throw NoiseCoreError.invalidMessage("Unexpected trailing bytes.")
        }

        self.keyPayloads = keyPayloads
        self.payload = payload
    }

    private static func readUInt16(from data: Data, cursor: inout Int) throws -> UInt16 {
        guard cursor + 2 <= data.count else {
            throw NoiseCoreError.invalidMessage("Truncated uint16.")
        }
        let upper = UInt16(data[cursor]) << 8
        let lower = UInt16(data[cursor + 1])
        cursor += 2
        return upper | lower
    }

    private static func readBytes(from data: Data, length: Int, cursor: inout Int) throws -> Data {
        guard cursor + length <= data.count else {
            throw NoiseCoreError.invalidMessage("Truncated byte segment.")
        }
        let segment = data[cursor..<(cursor + length)]
        cursor += length
        return Data(segment)
    }
}

private extension Data {
    mutating func appendUInt16(_ value: UInt16) {
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8(value & 0xFF))
    }
}

public struct NoiseHandshakeState: Sendable {
    public let configuration: NoiseHandshakeConfiguration
    public let pattern: NoiseHandshakePatternDefinition
    public private(set) var symmetricState: NoiseSymmetricState
    public private(set) var messageIndex: Int
    public private(set) var localStaticKey: NoiseDHKeyPair?
    public private(set) var localEphemeralKey: NoiseDHKeyPair?
    public private(set) var remoteStaticKey: Data?
    public private(set) var remoteEphemeralKey: Data?

    public init(configuration: NoiseHandshakeConfiguration, hash: any NoiseHashAlgorithm) throws {
        self.configuration = configuration
        pattern = NoiseHandshakePatterns.pattern(named: configuration.handshakePattern)
        symmetricState = NoiseSymmetricState(protocolName: configuration.protocolName, hash: hash)
        messageIndex = 0
        localStaticKey = configuration.localStaticKey
        localEphemeralKey = configuration.localEphemeralKey
        remoteStaticKey = configuration.remoteStaticKey
        remoteEphemeralKey = configuration.remoteEphemeralKey

        if !configuration.prologue.isEmpty {
            symmetricState.mixHash(configuration.prologue, hash: hash)
        }
        try mixPreMessages(hash: hash)
    }

    public var isComplete: Bool {
        messageIndex >= pattern.messages.count
    }

    public mutating func writeMessage(payload: Data, crypto: NoiseCryptoProvider) throws -> NoiseHandshakeMessage {
        let messagePattern = try currentMessagePattern()
        let actualDirection = localDirection
        guard messagePattern.direction == actualDirection else {
            throw NoiseCoreError.unexpectedMessageDirection(expected: messagePattern.direction, actual: actualDirection)
        }

        var keyPayloads: [Data] = []
        for token in messagePattern.tokens {
            switch token {
            case .e:
                let ephemeral = try ensureLocalEphemeral(using: crypto.diffieHellman)
                keyPayloads.append(ephemeral.publicKey)
                symmetricState.mixHash(ephemeral.publicKey, hash: crypto.hash)
            case .s:
                guard let staticKey = localStaticKey else {
                    throw NoiseCoreError.missingKeyMaterial("local static key")
                }
                let encodedStatic = try symmetricState.encryptAndHash(
                    staticKey.publicKey,
                    cipher: crypto.cipher,
                    hash: crypto.hash
                )
                keyPayloads.append(encodedStatic)
            case .ee, .es, .se, .ss:
                let sharedSecret = try dh(for: token, using: crypto.diffieHellman)
                try symmetricState.mixKey(sharedSecret, hash: crypto.hash)
            }
        }

        let ciphertextPayload = try symmetricState.encryptAndHash(
            payload,
            cipher: crypto.cipher,
            hash: crypto.hash
        )
        messageIndex += 1
        return NoiseHandshakeMessage(keyPayloads: keyPayloads, payload: ciphertextPayload)
    }

    public mutating func readMessage(_ message: NoiseHandshakeMessage, crypto: NoiseCryptoProvider) throws -> Data {
        let messagePattern = try currentMessagePattern()
        let actualDirection = remoteDirection
        guard messagePattern.direction == actualDirection else {
            throw NoiseCoreError.unexpectedMessageDirection(expected: messagePattern.direction, actual: actualDirection)
        }

        var keyPayloadIndex = 0
        for token in messagePattern.tokens {
            switch token {
            case .e:
                let remoteEphemeral = try consumeKeyPayload(
                    from: message.keyPayloads,
                    index: &keyPayloadIndex,
                    token: token
                )
                remoteEphemeralKey = remoteEphemeral
                symmetricState.mixHash(remoteEphemeral, hash: crypto.hash)
            case .s:
                let encodedStatic = try consumeKeyPayload(
                    from: message.keyPayloads,
                    index: &keyPayloadIndex,
                    token: token
                )
                let decryptedStatic = try symmetricState.decryptAndHash(
                    encodedStatic,
                    cipher: crypto.cipher,
                    hash: crypto.hash
                )
                remoteStaticKey = decryptedStatic
            case .ee, .es, .se, .ss:
                let sharedSecret = try dh(for: token, using: crypto.diffieHellman)
                try symmetricState.mixKey(sharedSecret, hash: crypto.hash)
            }
        }

        guard keyPayloadIndex == message.keyPayloads.count else {
            throw NoiseCoreError.invalidMessage("Unexpected extra key payloads.")
        }

        let plaintextPayload = try symmetricState.decryptAndHash(
            message.payload,
            cipher: crypto.cipher,
            hash: crypto.hash
        )
        messageIndex += 1
        return plaintextPayload
    }

    public func split(hash: any NoiseHashAlgorithm) throws -> NoiseTransportCipherStates {
        guard isComplete else {
            throw NoiseCoreError.handshakeNotComplete
        }
        return try symmetricState.split(hash: hash)
    }

    private var localDirection: NoiseMessageDirection {
        configuration.isInitiator ? .initiatorToResponder : .responderToInitiator
    }

    private var remoteDirection: NoiseMessageDirection {
        localDirection.inverted
    }

    private mutating func mixPreMessages(hash: any NoiseHashAlgorithm) throws {
        for preMessage in pattern.preMessages {
            for token in preMessage.tokens {
                let publicKey = try preMessagePublicKey(for: token, direction: preMessage.direction)
                symmetricState.mixHash(publicKey, hash: hash)
            }
        }
    }

    private func currentMessagePattern() throws -> NoisePatternMessage {
        guard messageIndex < pattern.messages.count else {
            throw NoiseCoreError.handshakeComplete
        }
        return pattern.messages[messageIndex]
    }

    private mutating func ensureLocalEphemeral(
        using diffieHellman: any NoiseDiffieHellmanAlgorithm
    ) throws -> NoiseDHKeyPair {
        if let localEphemeralKey {
            return localEphemeralKey
        }
        let generated = try diffieHellman.generateKeyPair()
        localEphemeralKey = generated
        return generated
    }

    private func preMessagePublicKey(
        for token: NoisePatternToken,
        direction: NoiseMessageDirection
    ) throws -> Data {
        let senderIsLocal = direction == localDirection
        switch token {
        case .s:
            if senderIsLocal {
                guard let localStaticKey else {
                    throw NoiseCoreError.missingKeyMaterial("local static key")
                }
                return localStaticKey.publicKey
            }
            guard let remoteStaticKey else {
                throw NoiseCoreError.missingKeyMaterial("remote static key")
            }
            return remoteStaticKey
        case .e:
            if senderIsLocal {
                guard let localEphemeralKey else {
                    throw NoiseCoreError.missingKeyMaterial("local ephemeral key")
                }
                return localEphemeralKey.publicKey
            }
            guard let remoteEphemeralKey else {
                throw NoiseCoreError.missingKeyMaterial("remote ephemeral key")
            }
            return remoteEphemeralKey
        default:
            throw NoiseCoreError.invalidMessage("Invalid pre-message token \(token.rawValue).")
        }
    }

    private func consumeKeyPayload(
        from keyPayloads: [Data],
        index: inout Int,
        token: NoisePatternToken
    ) throws -> Data {
        guard index < keyPayloads.count else {
            throw NoiseCoreError.invalidMessage("Missing key payload for token \(token.rawValue).")
        }
        defer { index += 1 }
        return keyPayloads[index]
    }

    private func dh(
        for token: NoisePatternToken,
        using diffieHellman: any NoiseDiffieHellmanAlgorithm
    ) throws -> Data {
        let input = try dhInput(for: token)
        return try diffieHellman.dh(privateKey: input.privateKey, publicKey: input.publicKey)
    }

    private func dhInput(for token: NoisePatternToken) throws -> (privateKey: Data, publicKey: Data) {
        switch token {
        case .ee:
            guard let localEphemeralKey else {
                throw NoiseCoreError.missingKeyMaterial("local ephemeral key")
            }
            guard let remoteEphemeralKey else {
                throw NoiseCoreError.missingKeyMaterial("remote ephemeral key")
            }
            return (localEphemeralKey.privateKey, remoteEphemeralKey)
        case .es:
            if configuration.isInitiator {
                guard let localEphemeralKey else {
                    throw NoiseCoreError.missingKeyMaterial("local ephemeral key")
                }
                guard let remoteStaticKey else {
                    throw NoiseCoreError.missingKeyMaterial("remote static key")
                }
                return (localEphemeralKey.privateKey, remoteStaticKey)
            }
            guard let localStaticKey else {
                throw NoiseCoreError.missingKeyMaterial("local static key")
            }
            guard let remoteEphemeralKey else {
                throw NoiseCoreError.missingKeyMaterial("remote ephemeral key")
            }
            return (localStaticKey.privateKey, remoteEphemeralKey)
        case .se:
            if configuration.isInitiator {
                guard let localStaticKey else {
                    throw NoiseCoreError.missingKeyMaterial("local static key")
                }
                guard let remoteEphemeralKey else {
                    throw NoiseCoreError.missingKeyMaterial("remote ephemeral key")
                }
                return (localStaticKey.privateKey, remoteEphemeralKey)
            }
            guard let localEphemeralKey else {
                throw NoiseCoreError.missingKeyMaterial("local ephemeral key")
            }
            guard let remoteStaticKey else {
                throw NoiseCoreError.missingKeyMaterial("remote static key")
            }
            return (localEphemeralKey.privateKey, remoteStaticKey)
        case .ss:
            guard let localStaticKey else {
                throw NoiseCoreError.missingKeyMaterial("local static key")
            }
            guard let remoteStaticKey else {
                throw NoiseCoreError.missingKeyMaterial("remote static key")
            }
            return (localStaticKey.privateKey, remoteStaticKey)
        default:
            throw NoiseCoreError.invalidMessage("Token \(token.rawValue) is not a DH token.")
        }
    }
}

public actor NoiseHandshakeSession {
    public private(set) var configuration: NoiseHandshakeConfiguration?
    private var state: NoiseHandshakeState?
    private var cryptoProvider: NoiseCryptoProvider?

    public init() {}

    public func initialize(with configuration: NoiseHandshakeConfiguration) {
        self.configuration = configuration
    }

    public func initialize(
        with configuration: NoiseHandshakeConfiguration,
        cryptoProvider: NoiseCryptoProvider
    ) throws {
        self.configuration = configuration
        self.cryptoProvider = cryptoProvider
        state = try NoiseHandshakeState(configuration: configuration, hash: cryptoProvider.hash)
    }

    public func writeMessageFrame(payload: Data) throws -> NoiseHandshakeMessage {
        guard var state, let cryptoProvider else {
            throw NoiseCoreError.handshakeNotInitialized
        }
        let message = try state.writeMessage(payload: payload, crypto: cryptoProvider)
        self.state = state
        return message
    }

    public func readMessageFrame(_ message: NoiseHandshakeMessage) throws -> Data {
        guard var state, let cryptoProvider else {
            throw NoiseCoreError.handshakeNotInitialized
        }
        let payload = try state.readMessage(message, crypto: cryptoProvider)
        self.state = state
        return payload
    }

    public func splitTransportStates() throws -> NoiseTransportCipherStates {
        guard let state, let cryptoProvider else {
            throw NoiseCoreError.handshakeNotInitialized
        }
        return try state.split(hash: cryptoProvider.hash)
    }

    public func writeMessage(payload: Data) async throws -> Data {
        try writeMessageFrame(payload: payload).encoded()
    }

    public func readMessage(_ message: Data) async throws -> Data {
        let messageFrame = try NoiseHandshakeMessage(encoded: message)
        return try readMessageFrame(messageFrame)
    }
}
