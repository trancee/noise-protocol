import CryptoKit
import Foundation
import NoiseCryptoAdapters
import Testing
@testable import NoiseCore

@Test("Core bootstrap exposes default protocol profile")
func bootstrapDefaultProtocolProfile() {
    #expect(NoiseCoreVersion.specificationRevision == 34)
    #expect(NoiseProtocolDescriptor.bootstrapDefault.rawValue == "Noise_XX_25519_AESGCM_SHA256")
}

@Test("Core exposes library version from canonical source")
func bootstrapLibraryVersion() throws {
    let sourceFile = URL(fileURLWithPath: #filePath)
    let testsDirectory = sourceFile.deletingLastPathComponent()
    let iosDirectory = testsDirectory.deletingLastPathComponent().deletingLastPathComponent()
    let repositoryDirectory = iosDirectory.deletingLastPathComponent()
    let canonicalVersionFile = repositoryDirectory.appendingPathComponent("VERSION")

    let canonicalVersion = try String(contentsOf: canonicalVersionFile, encoding: .utf8)
        .trimmingCharacters(in: .whitespacesAndNewlines)

    #expect(!canonicalVersion.isEmpty)
    #expect(NoiseCoreVersion.libraryVersion == canonicalVersion)
}

@Test("Protocol descriptors parse base patterns when PSK modifiers are present")
func protocolDescriptorParsesPskModifiers() {
    let descriptor = NoiseProtocolDescriptor(rawValue: "Noise_XXpsk0+psk2_25519_AESGCM_SHA256")
    #expect(NoiseHandshakePatternName(protocolDescriptor: descriptor) == .xx)
}

@Test("Protocol descriptors reject unsupported modifier grammar")
func protocolDescriptorRejectsUnsupportedModifierGrammar() {
    let descriptor = NoiseProtocolDescriptor(rawValue: "Noise_XXfallback_25519_AESGCM_SHA256")
    #expect(NoiseHandshakePatternName(protocolDescriptor: descriptor) == nil)
}

@Test("Pattern table ordering is correct for all currently supported handshake patterns")
func handshakePatternTableOrdering() {
    let expected: [(NoiseHandshakePatternName, [NoisePatternMessage], [NoisePatternMessage])] = [
        (
            .n,
            [NoisePatternMessage(direction: .responderToInitiator, tokens: [.s])],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es]),
            ]
        ),
        (
            .k,
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.s]),
            ],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es, .ss]),
            ]
        ),
        (
            .x,
            [NoisePatternMessage(direction: .responderToInitiator, tokens: [.s])],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es, .s, .ss]),
            ]
        ),
        (
            .nn,
            [],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee]),
            ]
        ),
        (
            .nk,
            [NoisePatternMessage(direction: .responderToInitiator, tokens: [.s])],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee]),
            ]
        ),
        (
            .nx,
            [],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .s, .es]),
            ]
        ),
        (
            .xn,
            [],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee]),
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s, .se]),
            ]
        ),
        (
            .xk,
            [NoisePatternMessage(direction: .responderToInitiator, tokens: [.s])],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee]),
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s, .se]),
            ]
        ),
        (
            .kn,
            [NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s])],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se]),
            ]
        ),
        (
            .kk,
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.s]),
            ],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es, .ss]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se]),
            ]
        ),
        (
            .kx,
            [NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s])],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se, .s, .es]),
            ]
        ),
        (
            .in,
            [],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .s]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se]),
            ]
        ),
        (
            .ik,
            [NoisePatternMessage(direction: .responderToInitiator, tokens: [.s])],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es, .s, .ss]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se]),
            ]
        ),
        (
            .ix,
            [],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .s]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se, .s, .es]),
            ]
        ),
        (
            .xx,
            [],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .s, .es]),
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.s, .se]),
            ]
        ),
    ]

    #expect(NoiseHandshakePatterns.all.count == 15)
    for (name, preMessages, messages) in expected {
        let pattern = NoiseHandshakePatterns.pattern(named: name)
        #expect(pattern.preMessages == preMessages)
        #expect(pattern.messages == messages)
    }
}

@Test("Handshake sequencing enforces direction and rejects out-of-order reads")
func handshakeSequencingDirectionValidation() throws {
    let crypto = NoiseCryptoProvider(
        diffieHellman: FakeDiffieHellmanAlgorithm(),
        cipher: FakeCipherAlgorithm(),
        hash: FakeHashAlgorithm()
    )

    var initiator = try NoiseHandshakeState(
        configuration: NoiseHandshakeConfiguration(
            protocolName: .bootstrapDefault,
            isInitiator: true,
            handshakePattern: .xx,
            localStaticKey: NoiseDHKeyPair(privateKey: Data([0xA1]), publicKey: Data([0xB1])),
            localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xA2]), publicKey: Data([0xB2]))
        ),
        hash: crypto.hash
    )

    var responder = try NoiseHandshakeState(
        configuration: NoiseHandshakeConfiguration(
            protocolName: .bootstrapDefault,
            isInitiator: false,
            handshakePattern: .xx,
            localStaticKey: NoiseDHKeyPair(privateKey: Data([0xC1]), publicKey: Data([0xD1])),
            localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xC2]), publicKey: Data([0xD2]))
        ),
        hash: crypto.hash
    )

    let message1 = try initiator.writeMessage(payload: Data("m1".utf8), crypto: crypto)
    let payload1 = try responder.readMessage(message1, crypto: crypto)
    #expect(payload1 == Data("m1".utf8))

    do {
        _ = try responder.readMessage(message1, crypto: crypto)
        Issue.record("Expected out-of-order direction error.")
    } catch let error as NoiseCoreError {
        if case let .unexpectedMessageDirection(expected, actual) = error {
            #expect(expected == .responderToInitiator)
            #expect(actual == .initiatorToResponder)
        } else {
            Issue.record("Unexpected NoiseCoreError: \(error)")
        }
    } catch {
        Issue.record("Unexpected error type: \(error)")
    }

    let message2 = try responder.writeMessage(payload: Data("m2".utf8), crypto: crypto)
    let payload2 = try initiator.readMessage(message2, crypto: crypto)
    #expect(payload2 == Data("m2".utf8))

    let message3 = try initiator.writeMessage(payload: Data("m3".utf8), crypto: crypto)
    let payload3 = try responder.readMessage(message3, crypto: crypto)
    #expect(payload3 == Data("m3".utf8))
    #expect(initiator.isComplete)
    #expect(responder.isComplete)
}

@Test("CipherState increments nonce and fails on overflow")
func cipherStateNonceBehavior() throws {
    var state = NoiseCipherState(key: Data([0x42]), nonce: 0)
    let cipher = FakeCipherAlgorithm()

    _ = try state.encryptWithAd(Data([0x01]), plaintext: Data([0x02]), using: cipher)
    _ = try state.decryptWithAd(Data([0x01]), ciphertext: Data([0x01, 0x42]), using: cipher)
    #expect(state.nonce == 2)

    var overflow = NoiseCipherState(key: Data([0x99]), nonce: .max)
    do {
        _ = try overflow.encryptWithAd(Data(), plaintext: Data([0x01]), using: cipher)
        Issue.record("Expected nonce overflow.")
    } catch let error as NoiseCoreError {
        #expect(error == .nonceOverflow)
    } catch {
        Issue.record("Unexpected error type: \(error)")
    }

    try state.setNonce(5)
    #expect(state.nonce == 5)

    do {
        try state.setNonce(4)
        Issue.record("Expected nonce regression to be rejected.")
    } catch let error as NoiseCoreError {
        if case let .invalidNonce(expectedMinimum, actual) = error {
            #expect(expectedMinimum == 5)
            #expect(actual == 4)
        } else {
            Issue.record("Unexpected NoiseCoreError: \(error)")
        }
    } catch {
        Issue.record("Unexpected error type: \(error)")
    }
}

@Test("CipherState preserves nonce when decrypt authentication fails")
func cipherStatePreservesNonceOnDecryptFailure() throws {
    var state = NoiseCipherState(key: Data([0x42]), nonce: 0)
    let cipher = FakeCipherAlgorithm()

    do {
        _ = try state.decryptWithAd(Data([0x01]), ciphertext: Data([0x99, 0x98]), using: cipher)
        Issue.record("Expected decrypt authentication failure.")
    } catch {
        #expect(state.nonce == 0)
    }

    let ciphertext = try state.encryptWithAd(Data([0x01]), plaintext: Data([0x02]), using: cipher)
    #expect(state.nonce == 1)

    var receiver = NoiseCipherState(key: Data([0x42]), nonce: 0)
    let plaintext = try receiver.decryptWithAd(Data([0x01]), ciphertext: ciphertext, using: cipher)
    #expect(plaintext == Data([0x02]))
    #expect(receiver.nonce == 1)
}

@Test("SymmetricState is deterministic with fake crypto")
func symmetricStateDeterministicWithFakeCrypto() throws {
    let hash = FakeHashAlgorithm()
    let cipher = FakeCipherAlgorithm()

    var sender = NoiseSymmetricState(protocolName: .bootstrapDefault, hash: hash)
    var receiver = NoiseSymmetricState(protocolName: .bootstrapDefault, hash: hash)

    sender.mixHash(Data("prologue".utf8), hash: hash)
    receiver.mixHash(Data("prologue".utf8), hash: hash)
    try sender.mixKey(Data("ikm".utf8), hash: hash)
    try receiver.mixKey(Data("ikm".utf8), hash: hash)

    let plaintext = Data("deterministic-payload".utf8)
    let ciphertext = try sender.encryptAndHash(plaintext, cipher: cipher, hash: hash)
    let decrypted = try receiver.decryptAndHash(ciphertext, cipher: cipher, hash: hash)

    #expect(decrypted == plaintext)
    #expect(sender.handshakeHash == receiver.handshakeHash)
    #expect(sender.chainingKey == receiver.chainingKey)

    let senderSplit = try sender.split(hash: hash)
    let receiverSplit = try receiver.split(hash: hash)
    #expect(senderSplit == receiverSplit)
}

@Test("SymmetricState mixKeyAndHash is deterministic with fake crypto")
func symmetricStateMixKeyAndHashDeterministic() throws {
    let hash = FakeHashAlgorithm()
    let cipher = FakeCipherAlgorithm()

    var sender = NoiseSymmetricState(
        protocolName: NoiseProtocolDescriptor(rawValue: "Noise_XXpsk2_25519_AESGCM_SHA256"),
        hash: hash
    )
    var receiver = NoiseSymmetricState(
        protocolName: NoiseProtocolDescriptor(rawValue: "Noise_XXpsk2_25519_AESGCM_SHA256"),
        hash: hash
    )

    try sender.mixKeyAndHash(Data([0x09, 0x08, 0x07, 0x06]), hash: hash)
    try receiver.mixKeyAndHash(Data([0x09, 0x08, 0x07, 0x06]), hash: hash)

    let plaintext = Data("deterministic-payload".utf8)
    let ciphertext = try sender.encryptAndHash(plaintext, cipher: cipher, hash: hash)
    let decrypted = try receiver.decryptAndHash(ciphertext, cipher: cipher, hash: hash)

    #expect(decrypted == plaintext)
    #expect(sender.handshakeHash == receiver.handshakeHash)
    #expect(sender.chainingKey == receiver.chainingKey)
}

@Test("Handshake message encoding round-trips key payloads and body")
func handshakeMessageEncodingRoundTrip() throws {
    let message = NoiseHandshakeMessage(
        keyPayloads: [Data([0x01, 0x02]), Data([0x03, 0x04, 0x05])],
        payload: Data("payload".utf8)
    )

    let encoded = try message.encoded()
    let decoded = try NoiseHandshakeMessage(encoded: encoded)

    #expect(decoded == message)
}

@Test("Handshake message encoding rejects frames above the Noise message limit")
func handshakeMessageEncodingRejectsOversizedFrames() throws {
    let oversized = NoiseHandshakeMessage(
        keyPayloads: [Data(repeating: 0xAA, count: 32_767)],
        payload: Data(repeating: 0xBB, count: 32_766)
    )

    do {
        _ = try oversized.encoded()
        Issue.record("Expected oversized message to be rejected.")
    } catch let error as NoiseCoreError {
        if case let .invalidMessage(detail) = error {
            #expect(detail.contains("65"))
        } else {
            Issue.record("Unexpected NoiseCoreError: \(error)")
        }
    } catch {
        Issue.record("Unexpected error type: \(error)")
    }
}

@Test("Handshake session exposes handshake hash for channel binding")
func handshakeSessionExposesHandshakeHash() async throws {
    let crypto = NoiseCryptoProvider(
        diffieHellman: FakeDiffieHellmanAlgorithm(),
        cipher: FakeCipherAlgorithm(),
        hash: FakeHashAlgorithm()
    )
    let configuration = NoiseHandshakeConfiguration(
        protocolName: .bootstrapDefault,
        isInitiator: true,
        handshakePattern: .xx,
        localStaticKey: NoiseDHKeyPair(privateKey: Data([0xA1]), publicKey: Data([0xB1])),
        localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xA2]), publicKey: Data([0xB2]))
    )

    var expectedState = try NoiseHandshakeState(configuration: configuration, hash: crypto.hash)
    let session = NoiseHandshakeSession()
    try await session.initialize(with: configuration, cryptoProvider: crypto)

    #expect(try await session.handshakeHash() == expectedState.handshakeHash)

    let payload = Data("channel-binding".utf8)
    _ = try expectedState.writeMessage(payload: payload, crypto: crypto)
    _ = try await session.writeMessageFrame(payload: payload)

    #expect(try await session.handshakeHash() == expectedState.handshakeHash)
}

@Test("Handshake session reports expected direction and completion progress")
func handshakeSessionReportsDirectionAndCompletion() async throws {
    let crypto = NoiseCryptoProvider(
        diffieHellman: FakeDiffieHellmanAlgorithm(),
        cipher: FakeCipherAlgorithm(),
        hash: FakeHashAlgorithm()
    )
    let initiatorConfiguration = NoiseHandshakeConfiguration(
        protocolName: .bootstrapDefault,
        isInitiator: true,
        handshakePattern: .xx,
        localStaticKey: NoiseDHKeyPair(privateKey: Data([0xA1]), publicKey: Data([0xB1])),
        localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xA2]), publicKey: Data([0xB2]))
    )
    let responderConfiguration = NoiseHandshakeConfiguration(
        protocolName: .bootstrapDefault,
        isInitiator: false,
        handshakePattern: .xx,
        localStaticKey: NoiseDHKeyPair(privateKey: Data([0xC1]), publicKey: Data([0xD1])),
        localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xC2]), publicKey: Data([0xD2]))
    )

    let initiator = NoiseHandshakeSession()
    let responder = NoiseHandshakeSession()
    try await initiator.initialize(with: initiatorConfiguration, cryptoProvider: crypto)
    try await responder.initialize(with: responderConfiguration, cryptoProvider: crypto)

    #expect(try await initiator.expectedDirection() == .initiatorToResponder)
    #expect(!(try await initiator.isComplete()))
    #expect(try await responder.expectedDirection() == .initiatorToResponder)
    #expect(!(try await responder.isComplete()))

    let message1 = try await initiator.writeMessageFrame(payload: Data("m1".utf8))
    _ = try await responder.readMessageFrame(message1)
    #expect(try await initiator.expectedDirection() == .responderToInitiator)
    #expect(try await responder.expectedDirection() == .responderToInitiator)

    let message2 = try await responder.writeMessageFrame(payload: Data("m2".utf8))
    _ = try await initiator.readMessageFrame(message2)
    #expect(try await initiator.expectedDirection() == .initiatorToResponder)
    #expect(try await responder.expectedDirection() == .initiatorToResponder)

    let message3 = try await initiator.writeMessageFrame(payload: Data("m3".utf8))
    _ = try await responder.readMessageFrame(message3)
    #expect(try await initiator.expectedDirection() == nil)
    #expect(try await responder.expectedDirection() == nil)
    #expect(try await initiator.isComplete())
    #expect(try await responder.isComplete())
}

@Test("Handshake state supports PSK modifiers derived from protocol name")
func handshakeStateSupportsPskModifiersFromProtocolName() throws {
    let crypto = NoiseCryptoProvider(
        diffieHellman: FakeDiffieHellmanAlgorithm(),
        cipher: FakeCipherAlgorithm(),
        hash: FakeHashAlgorithm()
    )
    let protocolName = NoiseProtocolDescriptor(rawValue: "Noise_XXpsk0+psk2_25519_AESGCM_SHA256")
    let preSharedKeys = [
        0: Data([0x01, 0x03, 0x05, 0x07]),
        2: Data([0x02, 0x04, 0x06, 0x08]),
    ]

    var initiator = try NoiseHandshakeState(
        configuration: NoiseHandshakeConfiguration(
            protocolName: protocolName,
            isInitiator: true,
            handshakePattern: .xx,
            preSharedKeys: preSharedKeys,
            localStaticKey: NoiseDHKeyPair(privateKey: Data([0xA1]), publicKey: Data([0xB1])),
            localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xA2]), publicKey: Data([0xB2]))
        ),
        hash: crypto.hash
    )
    var responder = try NoiseHandshakeState(
        configuration: NoiseHandshakeConfiguration(
            protocolName: protocolName,
            isInitiator: false,
            handshakePattern: .xx,
            preSharedKeys: preSharedKeys,
            localStaticKey: NoiseDHKeyPair(privateKey: Data([0xC1]), publicKey: Data([0xD1])),
            localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xC2]), publicKey: Data([0xD2]))
        ),
        hash: crypto.hash
    )

    let message1 = try initiator.writeMessage(payload: Data("m1".utf8), crypto: crypto)
    #expect(message1.keyPayloads.count == 1)
    #expect(try responder.readMessage(message1, crypto: crypto) == Data("m1".utf8))

    let message2 = try responder.writeMessage(payload: Data("m2".utf8), crypto: crypto)
    #expect(message2.keyPayloads.count == 2)
    #expect(try initiator.readMessage(message2, crypto: crypto) == Data("m2".utf8))

    let message3 = try initiator.writeMessage(payload: Data("m3".utf8), crypto: crypto)
    #expect(message3.keyPayloads.count == 1)
    #expect(try responder.readMessage(message3, crypto: crypto) == Data("m3".utf8))

    #expect(initiator.isComplete)
    #expect(responder.isComplete)
    #expect(initiator.handshakeHash == responder.handshakeHash)
}

@Test("Handshake state rejects missing PSK material for protocol modifiers")
func handshakeStateRejectsMissingPskMaterial() {
    let hash = FakeHashAlgorithm()

    do {
        _ = try NoiseHandshakeState(
            configuration: NoiseHandshakeConfiguration(
                protocolName: NoiseProtocolDescriptor(rawValue: "Noise_NNpsk0_25519_AESGCM_SHA256"),
                isInitiator: true,
                handshakePattern: .nn,
                localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xA2]), publicKey: Data([0xB2]))
            ),
            hash: hash
        )
        Issue.record("Expected missing PSK material to be rejected.")
    } catch let error as NoiseCoreError {
        if case let .missingKeyMaterial(detail) = error {
            #expect(detail.contains("psk0"))
        } else {
            Issue.record("Unexpected NoiseCoreError: \(error)")
        }
    } catch {
        Issue.record("Unexpected error type: \(error)")
    }
}

@Test("Handshake state rejects unsupported protocol-name modifiers")
func handshakeStateRejectsUnsupportedProtocolNameModifiers() {
    let hash = FakeHashAlgorithm()

    do {
        _ = try NoiseHandshakeState(
            configuration: NoiseHandshakeConfiguration(
                protocolName: NoiseProtocolDescriptor(rawValue: "Noise_XXfallback_25519_AESGCM_SHA256"),
                isInitiator: true,
                handshakePattern: .xx,
                localStaticKey: NoiseDHKeyPair(privateKey: Data([0xA1]), publicKey: Data([0xB1])),
                localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xA2]), publicKey: Data([0xB2]))
            ),
            hash: hash
        )
        Issue.record("Expected unsupported modifiers to be rejected.")
    } catch let error as NoiseCoreError {
        if case let .invalidMessage(detail) = error {
            #expect(detail.contains("Only base patterns and pskN modifiers"))
        } else {
            Issue.record("Unexpected NoiseCoreError: \(error)")
        }
    } catch {
        Issue.record("Unexpected error type: \(error)")
    }
}

@Test("Handshake state rejects protocol-name pattern mismatches")
func handshakeStateRejectsProtocolNamePatternMismatches() {
    let hash = FakeHashAlgorithm()

    do {
        _ = try NoiseHandshakeState(
            configuration: NoiseHandshakeConfiguration(
                protocolName: NoiseProtocolDescriptor(rawValue: "Noise_XX_25519_AESGCM_SHA256"),
                isInitiator: true,
                handshakePattern: .nn,
                localEphemeralKey: NoiseDHKeyPair(privateKey: Data([0xA2]), publicKey: Data([0xB2]))
            ),
            hash: hash
        )
        Issue.record("Expected protocol-name pattern mismatch to be rejected.")
    } catch let error as NoiseCoreError {
        if case let .invalidMessage(detail) = error {
            #expect(detail.contains("does not match selected handshake pattern"))
        } else {
            Issue.record("Unexpected NoiseCoreError: \(error)")
        }
    } catch {
        Issue.record("Unexpected error type: \(error)")
    }
}

@Test("Benchmark deterministic handshake throughput across patterns and built-in suites")
func benchmarkDeterministicHandshakeThroughput() throws {
    let payloadByStep = [
        Data("benchmark-message-1".utf8),
        Data("benchmark-message-2".utf8),
        Data("benchmark-message-3".utf8),
    ]
    let roundsPerVariation = 20
    let suites = benchmarkSuites()
    let patterns = NoiseHandshakePatternName.allCases
    let keyMaterial = try makeBenchmarkKeyMaterial()

    var completedRoundsTotal = 0
    let expectedRoundsTotal = suites.count * patterns.count * roundsPerVariation
    let overallStart = Date()

    for suite in suites {
        let crypto = makeBuiltInCryptoProvider(for: suite)
        for pattern in patterns {
            let messages = NoiseHandshakePatterns.pattern(named: pattern).messages
            var completedRounds = 0
            var referenceTranscript: [NoiseHandshakeMessage]?
            let start = Date()

            for round in 0..<roundsPerVariation {
                var initiator = try makeBenchmarkHandshakeState(
                    isInitiator: true,
                    pattern: pattern,
                    suite: suite,
                    keyMaterial: keyMaterial,
                    hash: crypto.hash
                )
                var responder = try makeBenchmarkHandshakeState(
                    isInitiator: false,
                    pattern: pattern,
                    suite: suite,
                    keyMaterial: keyMaterial,
                    hash: crypto.hash
                )

                var transcript: [NoiseHandshakeMessage] = []
                var roundFailed = false

                for (index, messagePattern) in messages.enumerated() {
                    let payload = payloadByStep[index]
                    switch messagePattern.direction {
                    case .initiatorToResponder:
                        let message = try initiator.writeMessage(payload: payload, crypto: crypto)
                        let recovered = try responder.readMessage(message, crypto: crypto)
                        guard recovered == payload else {
                            Issue.record(
                                "Round \(round): payload mismatch for \(pattern.rawValue) (\(suite.cipher)/\(suite.hash)) at step \(index + 1)."
                            )
                            roundFailed = true
                            break
                        }
                        transcript.append(message)
                    case .responderToInitiator:
                        let message = try responder.writeMessage(payload: payload, crypto: crypto)
                        let recovered = try initiator.readMessage(message, crypto: crypto)
                        guard recovered == payload else {
                            Issue.record(
                                "Round \(round): payload mismatch for \(pattern.rawValue) (\(suite.cipher)/\(suite.hash)) at step \(index + 1)."
                            )
                            roundFailed = true
                            break
                        }
                        transcript.append(message)
                    }
                }

                guard !roundFailed else {
                    break
                }

                guard initiator.isComplete, responder.isComplete else {
                    Issue.record("Round \(round): \(pattern.rawValue) handshake did not complete.")
                    break
                }

                if let referenceTranscript {
                    guard transcript == referenceTranscript else {
                        Issue.record(
                            "Round \(round): transcript diverged for \(pattern.rawValue) (\(suite.cipher)/\(suite.hash))."
                        )
                        break
                    }
                } else {
                    referenceTranscript = transcript
                }

                completedRounds += 1
                completedRoundsTotal += 1
            }

            let duration = Date().timeIntervalSince(start)
            let throughput = Double(completedRounds) / max(duration, .leastNonzeroMagnitude)

            print(
                "NoiseCore benchmark handshake variation: pattern=\(pattern.rawValue), dh=\(suite.diffieHellman), cipher=\(suite.cipher), hash=\(suite.hash), rounds=\(completedRounds)/\(roundsPerVariation), duration=\(String(format: "%.6f", duration))s, throughput=\(String(format: "%.2f", throughput)) rounds/s"
            )

            #expect(completedRounds == roundsPerVariation)
            #expect(referenceTranscript != nil)
            #expect(throughput > 0)
        }
    }

    let duration = Date().timeIntervalSince(overallStart)
    let throughput = Double(completedRoundsTotal) / max(duration, .leastNonzeroMagnitude)

    print(
        "NoiseCore benchmark handshake: rounds=\(completedRoundsTotal)/\(expectedRoundsTotal), duration=\(String(format: "%.6f", duration))s, throughput=\(String(format: "%.2f", throughput)) rounds/s"
    )

    #expect(completedRoundsTotal == expectedRoundsTotal)
    #expect(throughput > 0)
}

@Test("Benchmark transport cipher throughput across built-in suites")
func benchmarkTransportCipherThroughput() throws {
    let setupPayloads = [
        Data("transport-setup-1".utf8),
        Data("transport-setup-2".utf8),
        Data("transport-setup-3".utf8),
    ]
    let associatedData = Data("benchmark-associated-data".utf8)
    let plaintext = Data(repeating: 0x5A, count: 128)
    let iterationsPerVariation = 2_000
    let suites = benchmarkSuites()
    let keyMaterial = try makeBenchmarkKeyMaterial()

    var completedIterationsTotal = 0
    var processedBytesTotal = 0
    let expectedIterationsTotal = suites.count * iterationsPerVariation
    let overallStart = Date()

    for suite in suites {
        let crypto = makeBuiltInCryptoProvider(for: suite)
        let messages = NoiseHandshakePatterns.pattern(named: .xx).messages
        var initiator = try makeBenchmarkHandshakeState(
            isInitiator: true,
            pattern: .xx,
            suite: suite,
            keyMaterial: keyMaterial,
            hash: crypto.hash
        )
        var responder = try makeBenchmarkHandshakeState(
            isInitiator: false,
            pattern: .xx,
            suite: suite,
            keyMaterial: keyMaterial,
            hash: crypto.hash
        )

        for (index, messagePattern) in messages.enumerated() {
            let payload = setupPayloads[index]
            switch messagePattern.direction {
            case .initiatorToResponder:
                let message = try initiator.writeMessage(payload: payload, crypto: crypto)
                #expect(try responder.readMessage(message, crypto: crypto) == payload)
            case .responderToInitiator:
                let message = try responder.writeMessage(payload: payload, crypto: crypto)
                #expect(try initiator.readMessage(message, crypto: crypto) == payload)
            }
        }

        #expect(initiator.isComplete)
        #expect(responder.isComplete)

        let initiatorTransport = try initiator.split(hash: crypto.hash)
        let responderTransport = try responder.split(hash: crypto.hash)
        var sender = initiatorTransport.initiatorToResponder
        var receiver = responderTransport.initiatorToResponder

        var completedIterations = 0
        var processedBytes = 0
        let start = Date()

        for iteration in 0..<iterationsPerVariation {
            let ciphertext = try sender.encryptWithAd(associatedData, plaintext: plaintext, using: crypto.cipher)
            let decrypted = try receiver.decryptWithAd(associatedData, ciphertext: ciphertext, using: crypto.cipher)

            guard decrypted == plaintext else {
                Issue.record(
                    "Transport decrypt mismatch at iteration \(iteration) for \(suite.cipher)/\(suite.hash)."
                )
                break
            }

            completedIterations += 1
            processedBytes += plaintext.count
        }

        let duration = Date().timeIntervalSince(start)
        let operationsPerSecond = Double(completedIterations) / max(duration, .leastNonzeroMagnitude)
        let mebibytesPerSecond = Double(processedBytes) / max(duration, .leastNonzeroMagnitude) / 1_048_576.0

        print(
            "NoiseCore benchmark transport variation: dh=\(suite.diffieHellman), cipher=\(suite.cipher), hash=\(suite.hash), iterations=\(completedIterations)/\(iterationsPerVariation), duration=\(String(format: "%.6f", duration))s, throughput=\(String(format: "%.2f", operationsPerSecond)) ops/s, data=\(String(format: "%.2f", mebibytesPerSecond)) MiB/s"
        )

        #expect(completedIterations == iterationsPerVariation)
        #expect(sender.nonce == UInt64(iterationsPerVariation))
        #expect(receiver.nonce == UInt64(iterationsPerVariation))
        #expect(operationsPerSecond > 0)

        completedIterationsTotal += completedIterations
        processedBytesTotal += processedBytes
    }

    let duration = Date().timeIntervalSince(overallStart)
    let operationsPerSecond = Double(completedIterationsTotal) / max(duration, .leastNonzeroMagnitude)
    let mebibytesPerSecond = Double(processedBytesTotal) / max(duration, .leastNonzeroMagnitude) / 1_048_576.0

    print(
        "NoiseCore benchmark transport: iterations=\(completedIterationsTotal)/\(expectedIterationsTotal), duration=\(String(format: "%.6f", duration))s, throughput=\(String(format: "%.2f", operationsPerSecond)) ops/s, data=\(String(format: "%.2f", mebibytesPerSecond)) MiB/s"
    )

    #expect(completedIterationsTotal == expectedIterationsTotal)
    #expect(operationsPerSecond > 0)
}

private struct BenchmarkSuite: Sendable {
    let diffieHellman: String
    let cipher: String
    let hash: String
}

private struct BenchmarkKeyMaterial {
    let initiatorStatic: NoiseDHKeyPair
    let initiatorEphemeral: NoiseDHKeyPair
    let responderStatic: NoiseDHKeyPair
    let responderEphemeral: NoiseDHKeyPair
}

private func benchmarkSuites() -> [BenchmarkSuite] {
    let ciphers = ["ChaChaPoly", "AESGCM"]
    let hashes = ["SHA256", "SHA512"]
    return ciphers.flatMap { cipher in
        hashes.map { hash in
            BenchmarkSuite(diffieHellman: "25519", cipher: cipher, hash: hash)
        }
    }
}

private func makeBuiltInCryptoProvider(for suite: BenchmarkSuite) -> NoiseCryptoProvider {
    let cipher: any NoiseCipherAlgorithm
    switch suite.cipher {
    case "ChaChaPoly":
        cipher = ChaChaPolyCipherAdapter()
    case "AESGCM":
        cipher = AESGCMCipherAdapter()
    default:
        preconditionFailure("Unsupported benchmark cipher: \(suite.cipher)")
    }

    let hash: any NoiseHashAlgorithm
    switch suite.hash {
    case "SHA256":
        hash = SHA256HashAdapter()
    case "SHA512":
        hash = SHA512HashAdapter()
    default:
        preconditionFailure("Unsupported benchmark hash: \(suite.hash)")
    }

    return NoiseCryptoProvider(
        diffieHellman: Curve25519DiffieHellmanAdapter(),
        cipher: cipher,
        hash: hash
    )
}

private func makeBenchmarkKeyMaterial() throws -> BenchmarkKeyMaterial {
    BenchmarkKeyMaterial(
        initiatorStatic: try makeDeterministicCurve25519KeyPair(seed: 0x11),
        initiatorEphemeral: try makeDeterministicCurve25519KeyPair(seed: 0x31),
        responderStatic: try makeDeterministicCurve25519KeyPair(seed: 0x51),
        responderEphemeral: try makeDeterministicCurve25519KeyPair(seed: 0x71)
    )
}

private func makeDeterministicCurve25519KeyPair(seed: UInt8) throws -> NoiseDHKeyPair {
    let privateKeyMaterial = Data((0..<32).map { offset in
        seed &+ UInt8(offset)
    })
    let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyMaterial)
    return NoiseDHKeyPair(
        privateKey: privateKey.rawRepresentation,
        publicKey: privateKey.publicKey.rawRepresentation
    )
}

private func makeBenchmarkHandshakeState(
    isInitiator: Bool,
    pattern: NoiseHandshakePatternName,
    suite: BenchmarkSuite,
    keyMaterial: BenchmarkKeyMaterial,
    hash: any NoiseHashAlgorithm
) throws -> NoiseHandshakeState {
    let localStaticKey: NoiseDHKeyPair?
    let remoteStaticKey: Data?

    switch pattern {
    case .n:
        localStaticKey = isInitiator ? nil : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : nil
    case .k:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : keyMaterial.initiatorStatic.publicKey
    case .x:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : nil
    case .nn:
        localStaticKey = nil
        remoteStaticKey = nil
    case .nk:
        localStaticKey = isInitiator ? nil : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : nil
    case .nx:
        localStaticKey = isInitiator ? nil : keyMaterial.responderStatic
        remoteStaticKey = nil
    case .xn:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : nil
        remoteStaticKey = nil
    case .xk:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : nil
    case .kn:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : nil
        remoteStaticKey = isInitiator ? nil : keyMaterial.initiatorStatic.publicKey
    case .kk:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : keyMaterial.initiatorStatic.publicKey
    case .kx:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? nil : keyMaterial.initiatorStatic.publicKey
    case .in:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : nil
        remoteStaticKey = nil
    case .ik:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : nil
    case .ix:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = nil
    case .xx:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = nil
    }

    let configuration = NoiseHandshakeConfiguration(
        protocolName: NoiseProtocolDescriptor(
            rawValue: "Noise_\(pattern.rawValue)_\(suite.diffieHellman)_\(suite.cipher)_\(suite.hash)"
        ),
        isInitiator: isInitiator,
        handshakePattern: pattern,
        localStaticKey: localStaticKey,
        localEphemeralKey: isInitiator ? keyMaterial.initiatorEphemeral : keyMaterial.responderEphemeral,
        remoteStaticKey: remoteStaticKey
    )

    return try NoiseHandshakeState(configuration: configuration, hash: hash)
}

private struct FakeDiffieHellmanAlgorithm: NoiseDiffieHellmanAlgorithm {
    func generateKeyPair() throws -> NoiseDHKeyPair {
        NoiseDHKeyPair(privateKey: Data([0x10]), publicKey: Data([0x20]))
    }

    func dh(privateKey: Data, publicKey: Data) throws -> Data {
        let hash = FakeHashAlgorithm()
        var combined = Data()
        combined.append(privateKey)
        combined.append(publicKey)
        return hash.hash(combined)
    }
}

private struct FakeCipherAlgorithm: NoiseCipherAlgorithm {
    enum Error: Swift.Error {
        case invalidNonce
    }

    func encrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        plaintext: Data
    ) throws -> Data {
        let nonceByte = UInt8(truncatingIfNeeded: nonce)
        let mask = (key.first ?? 0) ^ UInt8(associatedData.count & 0xFF)

        var output = Data([nonceByte])
        output.append(contentsOf: plaintext.map { $0 ^ mask })
        return output
    }

    func decrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        ciphertext: Data
    ) throws -> Data {
        guard let receivedNonce = ciphertext.first else {
            return Data()
        }
        guard receivedNonce == UInt8(truncatingIfNeeded: nonce) else {
            throw Error.invalidNonce
        }

        let mask = (key.first ?? 0) ^ UInt8(associatedData.count & 0xFF)
        return Data(ciphertext.dropFirst().map { $0 ^ mask })
    }

    func rekey(_ key: Data) throws -> Data {
        Data(key.reversed())
    }
}

private struct FakeHashAlgorithm: NoiseHashAlgorithm {
    let hashLength: Int = 32

    func hash(_ data: Data) -> Data {
        let accumulator = data.reduce(0) { value, byte in
            (value + UInt64(byte)) & 0xFF
        }
        return Data((0..<hashLength).map { index in
            UInt8((Int(accumulator) + data.count + index) & 0xFF)
        })
    }

    func hkdf(chainingKey: Data, inputKeyMaterial: Data, outputCount: Int) -> [Data] {
        (0..<outputCount).map { counter in
            var material = Data()
            material.append(chainingKey)
            material.append(inputKeyMaterial)
            material.append(UInt8(counter & 0xFF))
            return hash(material)
        }
    }
}
