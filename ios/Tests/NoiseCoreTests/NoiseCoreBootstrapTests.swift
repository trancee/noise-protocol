import Foundation
import Testing
@testable import NoiseCore

@Test("Core bootstrap exposes default protocol profile")
func bootstrapDefaultProtocolProfile() {
    #expect(NoiseCoreVersion.specificationRevision == 34)
    #expect(NoiseProtocolDescriptor.bootstrapDefault.rawValue == "Noise_XX_25519_ChaChaPoly_BLAKE2s")
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
