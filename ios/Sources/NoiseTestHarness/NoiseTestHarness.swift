import Foundation
import NoiseCore
import NoiseCryptoAdapters

public enum NoiseTestHarnessError: Error, Sendable, Equatable {
    case fixtureDirectoryNotFound(String)
    case fixtureFileNotFound(String)
    case unsupportedSchemaVersion(String)
    case invalidHex(String)
    case invalidFixture(String)
    case payloadMismatch(index: Int)
    case expectedMessagesMismatch(expected: Int, actual: Int)
    case expectedMessageMismatch(index: Int)
    case expectedHandshakeHashMismatch
    case expectedSplitKeyMismatch
    case invalidExecutionHook(String)
    case expectedFailureDidNotOccur(caseID: String)
    case unexpectedNegativeErrorCode(caseID: String, expected: String, actual: String)
}

public enum NoiseVectorSender: String, Codable, Sendable, Equatable {
    case initiator
    case responder
}

public enum NoiseVectorPattern: String, Codable, Sendable, Equatable {
    case NN
    case NK
    case KK
    case IK
    case XX
}

public enum NoiseVectorDiffieHellman: String, Codable, Sendable, Equatable {
    case x25519 = "25519"
    case x448 = "448"
}

public enum NoiseVectorCipher: String, Codable, Sendable, Equatable {
    case chaChaPoly = "ChaChaPoly"
    case aesGCM = "AESGCM"
}

public enum NoiseVectorHash: String, Codable, Sendable, Equatable {
    case sha256 = "SHA256"
    case sha512 = "SHA512"
    case blake2s = "BLAKE2s"
    case blake2b = "BLAKE2b"
}

public struct NoiseVectorSuite: Codable, Sendable, Equatable {
    public var dh: NoiseVectorDiffieHellman
    public var cipher: NoiseVectorCipher
    public var hash: NoiseVectorHash
}

public struct NoiseVectorProtocol: Codable, Sendable, Equatable {
    public var name: String
    public var pattern: NoiseVectorPattern
    public var suite: NoiseVectorSuite
}

public struct NoiseVectorKeyPair: Codable, Sendable, Equatable {
    public var `private`: String
    public var `public`: String
}

public struct NoiseVectorPartyKeyMaterial: Codable, Sendable, Equatable {
    public var `static`: NoiseVectorKeyPair
    public var ephemeral: NoiseVectorKeyPair
}

public struct NoiseVectorKeyMaterial: Codable, Sendable, Equatable {
    public var initiator: NoiseVectorPartyKeyMaterial
    public var responder: NoiseVectorPartyKeyMaterial
}

public struct NoiseVectorPayloadInput: Codable, Sendable, Equatable {
    public var index: Int
    public var sender: NoiseVectorSender
    public var plaintextHex: String

    enum CodingKeys: String, CodingKey {
        case index
        case sender
        case plaintextHex = "plaintext_hex"
    }
}

public struct NoiseVectorInputs: Codable, Sendable, Equatable {
    public var prologue: String
    public var keyMaterial: NoiseVectorKeyMaterial
    public var payloads: [NoiseVectorPayloadInput]

    enum CodingKeys: String, CodingKey {
        case prologue
        case keyMaterial = "key_material"
        case payloads
    }
}

public struct NoiseVectorExpectedHandshakeMessage: Codable, Sendable, Equatable {
    public var index: Int
    public var sender: NoiseVectorSender
    public var messageHex: String

    enum CodingKeys: String, CodingKey {
        case index
        case sender
        case messageHex = "message_hex"
    }
}

public struct NoiseVectorExpectedTransportPartyKeys: Codable, Sendable, Equatable {
    public var tx: String
    public var rx: String
}

public struct NoiseVectorExpectedSplitTransportKeys: Codable, Sendable, Equatable {
    public var initiator: NoiseVectorExpectedTransportPartyKeys
    public var responder: NoiseVectorExpectedTransportPartyKeys
}

public struct NoiseVectorExpected: Codable, Sendable, Equatable {
    public var handshakeMessages: [NoiseVectorExpectedHandshakeMessage]
    public var handshakeHash: String
    public var splitTransportKeys: NoiseVectorExpectedSplitTransportKeys

    enum CodingKeys: String, CodingKey {
        case handshakeMessages = "handshake_messages"
        case handshakeHash = "handshake_hash"
        case splitTransportKeys = "split_transport_keys"
    }
}

public enum NoiseVectorNegativePhase: String, Codable, Sendable, Equatable {
    case handshake
    case transport
}

public enum NoiseVectorMutationTarget: String, Codable, Sendable, Equatable {
    case ciphertext
    case tag
    case payload
    case nonce
    case publicKey = "public_key"
    case messageOrder = "message_order"
}

public struct NoiseVectorMutation: Codable, Sendable, Equatable {
    public var target: NoiseVectorMutationTarget
    public var operation: String
}

public struct NoiseVectorExpectedError: Codable, Sendable, Equatable {
    public var code: String
    public var detail: String?
}

public struct NoiseVectorNegativeCase: Codable, Sendable, Equatable {
    public var id: String
    public var description: String
    public var phase: NoiseVectorNegativePhase
    public var messageIndex: Int?
    public var mutation: NoiseVectorMutation
    public var expectedError: NoiseVectorExpectedError

    enum CodingKeys: String, CodingKey {
        case id
        case description
        case phase
        case messageIndex = "message_index"
        case mutation
        case expectedError = "expected_error"
    }
}

public struct NoiseVectorFixture: Codable, Sendable, Equatable {
    public var schemaVersion: String
    public var vectorID: String
    public var description: String?
    public var protocolInfo: NoiseVectorProtocol
    public var inputs: NoiseVectorInputs
    public var expected: NoiseVectorExpected
    public var negativeCases: [NoiseVectorNegativeCase]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case vectorID = "vector_id"
        case description
        case protocolInfo = "protocol"
        case inputs
        case expected
        case negativeCases = "negative_cases"
    }
}

public struct NoiseVectorExecutionMessage: Sendable, Equatable {
    public var index: Int
    public var sender: NoiseVectorSender
    public var messageHex: String
}

public struct NoiseVectorExecutionTransportPartyKeys: Sendable, Equatable {
    public var txHex: String
    public var rxHex: String
}

public struct NoiseVectorExecutionSplitTransportKeys: Sendable, Equatable {
    public var initiator: NoiseVectorExecutionTransportPartyKeys
    public var responder: NoiseVectorExecutionTransportPartyKeys
}

public struct NoiseVectorExecutionResult: Sendable, Equatable {
    public var handshakeMessages: [NoiseVectorExecutionMessage]
    public var handshakeHashHex: String
    public var splitTransportKeys: NoiseVectorExecutionSplitTransportKeys
}

public struct NoiseVectorNegativeCaseResult: Sendable, Equatable {
    public var caseID: String
    public var expectedErrorCode: String
    public var actualErrorCode: String
}

public struct NoiseVectorFixtureLoader: Sendable {
    public static let defaultFixturesDirectory: URL = {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 {
            url.deleteLastPathComponent()
        }
        return url
            .appendingPathComponent("test-vectors")
            .appendingPathComponent("fixtures")
            .appendingPathComponent("v1", isDirectory: true)
    }()

    public let fixturesDirectory: URL

    public init(fixturesDirectory: URL = Self.defaultFixturesDirectory) {
        self.fixturesDirectory = fixturesDirectory
    }

    public func loadFixture(fileName: String) throws -> NoiseVectorFixture {
        let normalizedFileName = fileName.hasSuffix(".json") ? fileName : "\(fileName).json"
        guard FileManager.default.fileExists(atPath: fixturesDirectory.path) else {
            throw NoiseTestHarnessError.fixtureDirectoryNotFound(fixturesDirectory.path)
        }

        let fixtureURL = fixturesDirectory.appendingPathComponent(normalizedFileName)
        guard FileManager.default.fileExists(atPath: fixtureURL.path) else {
            throw NoiseTestHarnessError.fixtureFileNotFound(fixtureURL.path)
        }

        return try decodeFixture(at: fixtureURL)
    }

    public func loadFixture(vectorID: String) throws -> NoiseVectorFixture {
        let fixtures = try loadFixtures()
        guard let fixture = fixtures.first(where: { $0.vectorID == vectorID }) else {
            throw NoiseTestHarnessError.fixtureFileNotFound(vectorID)
        }
        return fixture
    }

    public func loadFixtures() throws -> [NoiseVectorFixture] {
        guard FileManager.default.fileExists(atPath: fixturesDirectory.path) else {
            throw NoiseTestHarnessError.fixtureDirectoryNotFound(fixturesDirectory.path)
        }

        let urls = try FileManager.default.contentsOfDirectory(
            at: fixturesDirectory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        return try urls.map(decodeFixture)
    }

    private func decodeFixture(at url: URL) throws -> NoiseVectorFixture {
        let data = try Data(contentsOf: url)
        let fixture = try JSONDecoder().decode(NoiseVectorFixture.self, from: data)
        guard fixture.schemaVersion.hasPrefix("1.") else {
            throw NoiseTestHarnessError.unsupportedSchemaVersion(fixture.schemaVersion)
        }
        return fixture
    }
}

public typealias NoiseVectorTamperHook = @Sendable (_ encodedMessage: Data, _ index: Int, _ sender: NoiseVectorSender) throws -> Data

public struct NoiseVectorExecutionHooks: Sendable {
    public var tamperEncodedMessage: NoiseVectorTamperHook?
    public var messageOrder: [Int]?

    public init(
        tamperEncodedMessage: NoiseVectorTamperHook? = nil,
        messageOrder: [Int]? = nil
    ) {
        self.tamperEncodedMessage = tamperEncodedMessage
        self.messageOrder = messageOrder
    }

    public static let none = NoiseVectorExecutionHooks()
}

public actor NoiseVectorRunner {
    public let fixtureLoader: NoiseVectorFixtureLoader
    private let registry: NoiseCryptoAdapterRegistry

    public init(
        registry: NoiseCryptoAdapterRegistry = .builtIn(),
        fixtureLoader: NoiseVectorFixtureLoader = .init()
    ) {
        self.registry = registry
        self.fixtureLoader = fixtureLoader
    }

    public func run(_ fixture: NoiseVectorFixture) async throws -> NoiseVectorExecutionResult {
        try await execute(fixture)
    }

    public func execute(
        _ fixture: NoiseVectorFixture,
        hooks: NoiseVectorExecutionHooks = .none
    ) async throws -> NoiseVectorExecutionResult {
        let provider = try await makeProvider(for: fixture)
        guard hooks.tamperEncodedMessage != nil || hooks.messageOrder != nil else {
            return try executeCanonical(fixture: fixture, provider: provider).result
        }

        let payloadSteps = try orderedPayloads(from: fixture.inputs.payloads)
        return try replay(
            fixture: fixture,
            provider: provider,
            payloadSteps: payloadSteps,
            hooks: hooks
        )
    }

    @discardableResult
    public func verifyExpected(_ fixture: NoiseVectorFixture) async throws -> NoiseVectorExecutionResult {
        let result = try await execute(fixture)
        try validate(expected: fixture.expected, against: result)
        return result
    }

    public func verifyNegativeCase(
        _ negativeCase: NoiseVectorNegativeCase,
        in fixture: NoiseVectorFixture
    ) async throws -> NoiseVectorNegativeCaseResult {
        guard negativeCase.phase == .handshake else {
            throw NoiseTestHarnessError.invalidExecutionHook("Only handshake negative cases are supported.")
        }

        let provider = try await makeProvider(for: fixture)
        let payloadSteps = try orderedPayloads(from: fixture.inputs.payloads)
        let hooks = try executionHooks(for: negativeCase, frameCount: payloadSteps.count)

        do {
            _ = try replay(
                fixture: fixture,
                provider: provider,
                payloadSteps: payloadSteps,
                hooks: hooks
            )
            throw NoiseTestHarnessError.expectedFailureDidNotOccur(caseID: negativeCase.id)
        } catch let error as NoiseTestHarnessError {
            if case .expectedFailureDidNotOccur = error {
                throw error
            }

            let actualCode = Self.errorCode(for: error)
            guard actualCode == negativeCase.expectedError.code else {
                throw NoiseTestHarnessError.unexpectedNegativeErrorCode(
                    caseID: negativeCase.id,
                    expected: negativeCase.expectedError.code,
                    actual: actualCode
                )
            }

            return NoiseVectorNegativeCaseResult(
                caseID: negativeCase.id,
                expectedErrorCode: negativeCase.expectedError.code,
                actualErrorCode: actualCode
            )
        } catch {
            let actualCode = Self.errorCode(for: error)
            guard actualCode == negativeCase.expectedError.code else {
                throw NoiseTestHarnessError.unexpectedNegativeErrorCode(
                    caseID: negativeCase.id,
                    expected: negativeCase.expectedError.code,
                    actual: actualCode
                )
            }

            return NoiseVectorNegativeCaseResult(
                caseID: negativeCase.id,
                expectedErrorCode: negativeCase.expectedError.code,
                actualErrorCode: actualCode
            )
        }
    }

    private func makeProvider(for fixture: NoiseVectorFixture) async throws -> NoiseCryptoProvider {
        try await registry.makeProvider(
            for: NoiseCryptoSuiteDescriptor(
                protocolName: NoiseProtocolDescriptor(rawValue: fixture.protocolInfo.name),
                diffieHellman: fixture.protocolInfo.suite.dh.rawValue,
                cipher: fixture.protocolInfo.suite.cipher.rawValue,
                hash: fixture.protocolInfo.suite.hash.rawValue
            )
        )
    }

    private func executeCanonical(
        fixture: NoiseVectorFixture,
        provider: NoiseCryptoProvider
    ) throws -> CanonicalExecution {
        var states = try makeHandshakeStates(fixture: fixture, provider: provider)
        let orderedPayloads = try orderedPayloads(from: fixture.inputs.payloads)

        var frames: [RecordedFrame] = []
        frames.reserveCapacity(orderedPayloads.count)

        for payloadStep in orderedPayloads {
            let plaintext = try Data(noiseHex: payloadStep.plaintextHex)

            switch payloadStep.sender {
            case .initiator:
                let outbound = try states.initiator.writeMessage(payload: plaintext, crypto: provider)
                let encoded = try outbound.encoded()
                let inbound = try NoiseHandshakeMessage(encoded: encoded)
                let received = try states.responder.readMessage(inbound, crypto: provider)
                guard received == plaintext else {
                    throw NoiseTestHarnessError.payloadMismatch(index: payloadStep.index)
                }
                frames.append(
                    RecordedFrame(
                        index: payloadStep.index,
                        sender: payloadStep.sender,
                        encodedMessage: encoded
                    )
                )

            case .responder:
                let outbound = try states.responder.writeMessage(payload: plaintext, crypto: provider)
                let encoded = try outbound.encoded()
                let inbound = try NoiseHandshakeMessage(encoded: encoded)
                let received = try states.initiator.readMessage(inbound, crypto: provider)
                guard received == plaintext else {
                    throw NoiseTestHarnessError.payloadMismatch(index: payloadStep.index)
                }
                frames.append(
                    RecordedFrame(
                        index: payloadStep.index,
                        sender: payloadStep.sender,
                        encodedMessage: encoded
                    )
                )
            }
        }

        let result = try executionResult(
            initiator: states.initiator,
            responder: states.responder,
            provider: provider,
            frames: frames
        )
        return CanonicalExecution(result: result, frames: frames)
    }

    private func replay(
        fixture: NoiseVectorFixture,
        provider: NoiseCryptoProvider,
        payloadSteps: [NoiseVectorPayloadInput],
        hooks: NoiseVectorExecutionHooks
    ) throws -> NoiseVectorExecutionResult {
        var states = try makeHandshakeStates(fixture: fixture, provider: provider)
        let replayOrder = try validatedReplayOrder(hooks.messageOrder, frameCount: payloadSteps.count)

        var replayedFrames: [RecordedFrame] = []
        replayedFrames.reserveCapacity(payloadSteps.count)

        for sourceIndex in replayOrder {
            let payloadStep = payloadSteps[sourceIndex]
            let plaintext = try Data(noiseHex: payloadStep.plaintextHex)

            let outboundMessage: NoiseHandshakeMessage
            switch payloadStep.sender {
            case .initiator:
                outboundMessage = try states.initiator.writeMessage(payload: plaintext, crypto: provider)
            case .responder:
                outboundMessage = try states.responder.writeMessage(payload: plaintext, crypto: provider)
            }

            var encodedMessage = try outboundMessage.encoded()
            if let tamperEncodedMessage = hooks.tamperEncodedMessage {
                encodedMessage = try tamperEncodedMessage(
                    encodedMessage,
                    payloadStep.index,
                    payloadStep.sender
                )
            }

            let decodedMessage = try NoiseHandshakeMessage(encoded: encodedMessage)
            switch payloadStep.sender {
            case .initiator:
                _ = try states.responder.readMessage(decodedMessage, crypto: provider)
            case .responder:
                _ = try states.initiator.readMessage(decodedMessage, crypto: provider)
            }

            replayedFrames.append(
                RecordedFrame(
                    index: payloadStep.index,
                    sender: payloadStep.sender,
                    encodedMessage: encodedMessage
                )
            )
        }

        return try executionResult(
            initiator: states.initiator,
            responder: states.responder,
            provider: provider,
            frames: replayedFrames
        )
    }

    private func executionResult(
        initiator: NoiseHandshakeState,
        responder: NoiseHandshakeState,
        provider: NoiseCryptoProvider,
        frames: [RecordedFrame]
    ) throws -> NoiseVectorExecutionResult {
        guard initiator.isComplete, responder.isComplete else {
            throw NoiseTestHarnessError.invalidFixture("Handshake transcript did not complete.")
        }

        guard initiator.symmetricState.handshakeHash == responder.symmetricState.handshakeHash else {
            throw NoiseTestHarnessError.invalidFixture("Initiator and responder transcript hashes diverged.")
        }

        let initiatorSplit = try initiator.split(hash: provider.hash)
        let responderSplit = try responder.split(hash: provider.hash)

        guard
            let initiatorTx = initiatorSplit.initiatorToResponder.key,
            let initiatorRx = initiatorSplit.responderToInitiator.key,
            let responderTx = responderSplit.responderToInitiator.key,
            let responderRx = responderSplit.initiatorToResponder.key
        else {
            throw NoiseTestHarnessError.invalidFixture("Transport keys were not produced.")
        }

        return NoiseVectorExecutionResult(
            handshakeMessages: frames.map {
                NoiseVectorExecutionMessage(
                    index: $0.index,
                    sender: $0.sender,
                    messageHex: $0.encodedMessage.noiseHexString
                )
            },
            handshakeHashHex: initiator.symmetricState.handshakeHash.noiseHexString,
            splitTransportKeys: NoiseVectorExecutionSplitTransportKeys(
                initiator: NoiseVectorExecutionTransportPartyKeys(
                    txHex: initiatorTx.noiseHexString,
                    rxHex: initiatorRx.noiseHexString
                ),
                responder: NoiseVectorExecutionTransportPartyKeys(
                    txHex: responderTx.noiseHexString,
                    rxHex: responderRx.noiseHexString
                )
            )
        )
    }

    private func makeHandshakeStates(
        fixture: NoiseVectorFixture,
        provider: NoiseCryptoProvider
    ) throws -> (initiator: NoiseHandshakeState, responder: NoiseHandshakeState) {
        guard let pattern = NoiseHandshakePatternName(rawValue: fixture.protocolInfo.pattern.rawValue) else {
            throw NoiseTestHarnessError.invalidFixture("Unsupported pattern \(fixture.protocolInfo.pattern.rawValue).")
        }

        let protocolName = NoiseProtocolDescriptor(rawValue: fixture.protocolInfo.name)
        let prologue = try Data(noiseHex: fixture.inputs.prologue)

        let initiatorStatic = try fixture.inputs.keyMaterial.initiator.static.asNoiseKeyPair()
        let initiatorEphemeral = try fixture.inputs.keyMaterial.initiator.ephemeral.asNoiseKeyPair()
        let responderStatic = try fixture.inputs.keyMaterial.responder.static.asNoiseKeyPair()
        let responderEphemeral = try fixture.inputs.keyMaterial.responder.ephemeral.asNoiseKeyPair()

        let initiatorConfiguration = NoiseHandshakeConfiguration(
            protocolName: protocolName,
            isInitiator: true,
            handshakePattern: pattern,
            prologue: prologue,
            localStaticKey: initiatorStatic,
            localEphemeralKey: initiatorEphemeral,
            remoteStaticKey: responderStatic.publicKey
        )

        let responderConfiguration = NoiseHandshakeConfiguration(
            protocolName: protocolName,
            isInitiator: false,
            handshakePattern: pattern,
            prologue: prologue,
            localStaticKey: responderStatic,
            localEphemeralKey: responderEphemeral,
            remoteStaticKey: initiatorStatic.publicKey
        )

        return (
            initiator: try NoiseHandshakeState(configuration: initiatorConfiguration, hash: provider.hash),
            responder: try NoiseHandshakeState(configuration: responderConfiguration, hash: provider.hash)
        )
    }

    private func orderedPayloads(
        from payloads: [NoiseVectorPayloadInput]
    ) throws -> [NoiseVectorPayloadInput] {
        let ordered = payloads.sorted { $0.index < $1.index }
        for (expectedIndex, payload) in ordered.enumerated() {
            guard payload.index == expectedIndex else {
                throw NoiseTestHarnessError.invalidFixture("Payload indexes must be sequential from zero.")
            }
        }
        return ordered
    }

    private func validatedReplayOrder(_ replayOrder: [Int]?, frameCount: Int) throws -> [Int] {
        guard let replayOrder else {
            return Array(0..<frameCount)
        }

        guard replayOrder.count == frameCount else {
            throw NoiseTestHarnessError.invalidExecutionHook("Replay order count must equal frame count.")
        }

        guard Set(replayOrder) == Set(0..<frameCount) else {
            throw NoiseTestHarnessError.invalidExecutionHook("Replay order must be a permutation of frame indexes.")
        }

        return replayOrder
    }

    private func validate(
        expected: NoiseVectorExpected,
        against actual: NoiseVectorExecutionResult
    ) throws {
        let expectedMessages = expected.handshakeMessages.sorted { $0.index < $1.index }
        let actualMessages = actual.handshakeMessages.sorted { $0.index < $1.index }

        guard expectedMessages.count == actualMessages.count else {
            throw NoiseTestHarnessError.expectedMessagesMismatch(
                expected: expectedMessages.count,
                actual: actualMessages.count
            )
        }

        for (expectedMessage, actualMessage) in zip(expectedMessages, actualMessages) {
            guard
                expectedMessage.index == actualMessage.index,
                expectedMessage.sender == actualMessage.sender,
                expectedMessage.messageHex.lowercased() == actualMessage.messageHex.lowercased()
            else {
                throw NoiseTestHarnessError.expectedMessageMismatch(index: expectedMessage.index)
            }
        }

        guard expected.handshakeHash.lowercased() == actual.handshakeHashHex.lowercased() else {
            throw NoiseTestHarnessError.expectedHandshakeHashMismatch
        }

        guard
            expected.splitTransportKeys.initiator.tx.lowercased() == actual.splitTransportKeys.initiator.txHex.lowercased(),
            expected.splitTransportKeys.initiator.rx.lowercased() == actual.splitTransportKeys.initiator.rxHex.lowercased(),
            expected.splitTransportKeys.responder.tx.lowercased() == actual.splitTransportKeys.responder.txHex.lowercased(),
            expected.splitTransportKeys.responder.rx.lowercased() == actual.splitTransportKeys.responder.rxHex.lowercased()
        else {
            throw NoiseTestHarnessError.expectedSplitKeyMismatch
        }
    }

    private func executionHooks(
        for negativeCase: NoiseVectorNegativeCase,
        frameCount: Int
    ) throws -> NoiseVectorExecutionHooks {
        switch negativeCase.mutation.target {
        case .messageOrder:
            guard negativeCase.mutation.operation == "swap_0_1" else {
                throw NoiseTestHarnessError.invalidExecutionHook(
                    "Unsupported message order operation \(negativeCase.mutation.operation)."
                )
            }
            guard frameCount > 1 else {
                throw NoiseTestHarnessError.invalidExecutionHook("Cannot swap message order with less than two messages.")
            }

            var replayOrder = Array(0..<frameCount)
            replayOrder.swapAt(0, 1)
            return NoiseVectorExecutionHooks(messageOrder: replayOrder)

        case .tag, .ciphertext, .payload, .publicKey:
            guard negativeCase.mutation.operation == "flip_last_bit" else {
                throw NoiseTestHarnessError.invalidExecutionHook(
                    "Unsupported tamper operation \(negativeCase.mutation.operation)."
                )
            }

            let targetIndex = negativeCase.messageIndex ?? 0
            guard targetIndex >= 0, targetIndex < frameCount else {
                throw NoiseTestHarnessError.invalidExecutionHook("Tamper message index is out of bounds.")
            }

            return NoiseVectorExecutionHooks(
                tamperEncodedMessage: { encodedMessage, index, _ in
                    guard index == targetIndex else {
                        return encodedMessage
                    }
                    guard !encodedMessage.isEmpty else {
                        throw NoiseTestHarnessError.invalidExecutionHook("Cannot tamper an empty message.")
                    }

                    var tampered = encodedMessage
                    let lastIndex = tampered.index(before: tampered.endIndex)
                    tampered[lastIndex] = tampered[lastIndex] ^ 0x01
                    return tampered
                }
            )

        case .nonce:
            throw NoiseTestHarnessError.invalidExecutionHook(
                "Nonce mutation is not supported by handshake replay hooks."
            )
        }
    }

    private static func errorCode(for error: Error) -> String {
        if let coreError = error as? NoiseCoreError {
            switch coreError {
            case .unexpectedMessageDirection:
                return "unexpected_message_order"
            default:
                return "decrypt_failed"
            }
        }

        if error is NoiseCryptoAdapterError {
            return "decrypt_failed"
        }

        if error is NoiseTestHarnessError {
            return "harness_error"
        }

        return "decrypt_failed"
    }
}

private struct RecordedFrame: Sendable {
    let index: Int
    let sender: NoiseVectorSender
    let encodedMessage: Data
}

private struct CanonicalExecution: Sendable {
    let result: NoiseVectorExecutionResult
    let frames: [RecordedFrame]
}

private extension NoiseVectorKeyPair {
    func asNoiseKeyPair() throws -> NoiseDHKeyPair {
        NoiseDHKeyPair(
            privateKey: try Data(noiseHex: `private`),
            publicKey: try Data(noiseHex: `public`)
        )
    }
}

private extension Data {
    init(noiseHex rawHex: String) throws {
        let normalized = rawHex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard normalized.count.isMultiple(of: 2) else {
            throw NoiseTestHarnessError.invalidHex(rawHex)
        }

        var data = Data()
        data.reserveCapacity(normalized.count / 2)

        var index = normalized.startIndex
        while index < normalized.endIndex {
            let nextIndex = normalized.index(index, offsetBy: 2)
            let byteString = normalized[index..<nextIndex]
            guard let byte = UInt8(byteString, radix: 16) else {
                throw NoiseTestHarnessError.invalidHex(rawHex)
            }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }

    var noiseHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
