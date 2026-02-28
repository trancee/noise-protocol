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

@Test("Pattern table ordering is correct for NN/NK/KK/IK/XX")
func handshakePatternTableOrdering() {
    let expected: [(NoiseHandshakePatternName, [NoisePatternMessage], [NoisePatternMessage])] = [
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
            .ik,
            [NoisePatternMessage(direction: .responderToInitiator, tokens: [.s])],
            [
                NoisePatternMessage(direction: .initiatorToResponder, tokens: [.e, .es, .s, .ss]),
                NoisePatternMessage(direction: .responderToInitiator, tokens: [.e, .ee, .se]),
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

    #expect(NoiseHandshakePatterns.all.count == 5)
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
    case .nn:
        localStaticKey = nil
        remoteStaticKey = nil
    case .nk:
        localStaticKey = isInitiator ? nil : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : nil
    case .kk:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : keyMaterial.initiatorStatic.publicKey
    case .ik:
        localStaticKey = isInitiator ? keyMaterial.initiatorStatic : keyMaterial.responderStatic
        remoteStaticKey = isInitiator ? keyMaterial.responderStatic.publicKey : nil
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
