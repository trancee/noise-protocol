import XCTest
@testable import NoiseProtocol
import Foundation

// MARK: - Hex helper

extension Data {
    init(hex: String) {
        let stripped = hex.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
        var data = Data(capacity: stripped.count / 2)
        var index = stripped.startIndex
        while index < stripped.endIndex {
            let nextIndex = stripped.index(index, offsetBy: 2)
            let byte = UInt8(stripped[index..<nextIndex], radix: 16)!
            data.append(byte)
            index = nextIndex
        }
        self = data
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Deterministic key generator that serves keys in order

final class SequentialKeyPairGenerator: KeyPairGenerator, @unchecked Sendable {
    private var keys: [Data]
    private var index = 0

    init(keys: [Data]) {
        self.keys = keys
    }

    func generate() -> NoiseKeyPair {
        let key = keys[index]
        index += 1
        return try! NoiseKeyPair(privateKeyData: key)
    }
}

// MARK: - Test vector message data

struct TestMessage {
    let payload: Data
    let ciphertext: Data
}

// MARK: - JSON Codable structs

private struct VectorMessage: Codable {
    let payload: String
    let ciphertext: String
}

private struct Vector: Codable {
    let name: String
    let pattern: String
    let initStatic: String?
    let respStatic: String?
    let initRemoteStatic: String?
    let respRemoteStatic: String?
    let psks: [String]
    let handshakeMessages: [VectorMessage]
    let transportMessages: [VectorMessage]
    let handshakeHash: String

    enum CodingKeys: String, CodingKey {
        case name, pattern, psks
        case initStatic = "init_static"
        case respStatic = "resp_static"
        case initRemoteStatic = "init_remote_static"
        case respRemoteStatic = "resp_remote_static"
        case handshakeMessages = "handshake_messages"
        case transportMessages = "transport_messages"
        case handshakeHash = "handshake_hash"
    }
}

private struct FallbackVector: Codable {
    let name: String
    let pattern: String
    let wrongRemoteStatic: String
    let fallbackPrologue: String
    let ikMessage1: VectorMessage
    let fallbackMessages: [VectorMessage]
    let handshakeHash: String
    let transportMessage: VectorMessage

    enum CodingKeys: String, CodingKey {
        case name, pattern
        case wrongRemoteStatic = "wrong_remote_static"
        case fallbackPrologue = "fallback_prologue"
        case ikMessage1 = "ik_message1"
        case fallbackMessages = "fallback_messages"
        case handshakeHash = "handshake_hash"
        case transportMessage = "transport_message"
    }
}

private struct VectorFile: Codable {
    let cipherSuite: String
    let keys: [String: String]
    let vectors: [Vector]
    let fallbackVectors: [FallbackVector]

    enum CodingKeys: String, CodingKey {
        case cipherSuite = "cipher_suite"
        case keys, vectors
        case fallbackVectors = "fallback_vectors"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        cipherSuite = try container.decode(String.self, forKey: .cipherSuite)
        keys = try container.decode([String: String].self, forKey: .keys)
        vectors = try container.decode([Vector].self, forKey: .vectors)
        fallbackVectors = try container.decodeIfPresent([FallbackVector].self, forKey: .fallbackVectors) ?? []
    }
}

// MARK: - Test Vector Tests

final class TestVectorTests: XCTestCase {

    // MARK: - Path resolution + JSON loading

    private static let testVectorsDir: URL = {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // → Tests/NoiseProtocolTests/
            .deletingLastPathComponent() // → Tests/
            .deletingLastPathComponent() // → ios/
            .deletingLastPathComponent() // → repo root
            .appendingPathComponent("test-vectors")
    }()

    private static func loadVectorFile(_ fileName: String) -> VectorFile {
        let url = testVectorsDir.appendingPathComponent("\(fileName).json")
        let data = try! Data(contentsOf: url)
        return try! JSONDecoder().decode(VectorFile.self, from: data)
    }

    // MARK: - Pattern name → HandshakePattern mapping

    private static let patternMap: [String: HandshakePattern] = [
        "NN": .NN, "NK": .NK, "KK": .KK, "IK": .IK, "XX": .XX,
        "NKpsk0": .NKpsk0, "IKpsk2": .IKpsk2,
    ]

    // MARK: - Key resolution helpers

    private func resolveKey(_ keyName: String?, keys: [String: String]) -> Data? {
        guard let keyName, let hex = keys[keyName] else { return nil }
        return Data(hex: hex)
    }

    private func resolveKeyRequired(_ keyName: String, keys: [String: String]) -> Data {
        guard let hex = keys[keyName] else {
            fatalError("Key '\(keyName)' not found in test vector keys")
        }
        return Data(hex: hex)
    }

    // MARK: - ChaChaPoly suites

    func testChaChaPoly_SHA256() throws {
        try runAllVectors(fileName: "noise_25519_ChaChaPoly_SHA256", suite: .noise_25519_ChaChaPoly_SHA256)
    }

    func testChaChaPoly_SHA512() throws {
        try runAllVectors(fileName: "noise_25519_ChaChaPoly_SHA512", suite: .noise_25519_ChaChaPoly_SHA512)
    }

    func testChaChaPoly_BLAKE2s() throws {
        try runAllVectors(fileName: "noise_25519_ChaChaPoly_BLAKE2s", suite: .noise_25519_ChaChaPoly_BLAKE2s)
    }

    func testChaChaPoly_BLAKE2b() throws {
        try runAllVectors(fileName: "noise_25519_ChaChaPoly_BLAKE2b", suite: .noise_25519_ChaChaPoly_BLAKE2b)
    }

    // MARK: - AESGCM suites

    func testAESGCM_SHA256() throws {
        try runAllVectors(fileName: "noise_25519_AESGCM_SHA256", suite: .noise_25519_AESGCM_SHA256)
    }

    func testAESGCM_SHA512() throws {
        try runAllVectors(fileName: "noise_25519_AESGCM_SHA512", suite: .noise_25519_AESGCM_SHA512)
    }

    func testAESGCM_BLAKE2s() throws {
        try runAllVectors(fileName: "noise_25519_AESGCM_BLAKE2s", suite: .noise_25519_AESGCM_BLAKE2s)
    }

    func testAESGCM_BLAKE2b() throws {
        try runAllVectors(fileName: "noise_25519_AESGCM_BLAKE2b", suite: .noise_25519_AESGCM_BLAKE2b)
    }

    // MARK: - XXfallback (only present in ChaChaPoly_SHA256)

    func testXXfallback() throws {
        let vf = Self.loadVectorFile("noise_25519_ChaChaPoly_SHA256")
        let suite = CipherSuite.noise_25519_ChaChaPoly_SHA256
        let keys = vf.keys
        let fb = vf.fallbackVectors[0]

        let initEphemeral = resolveKeyRequired("init_ephemeral", keys: keys)
        let respEphemeral = resolveKeyRequired("resp_ephemeral", keys: keys)
        let initStatic = resolveKeyRequired("init_static", keys: keys)
        let respStatic = resolveKeyRequired("resp_static", keys: keys)
        let initEphPub = resolveKeyRequired("init_eph_pub", keys: keys)
        let wrongRemoteStatic = Data(hex: fb.wrongRemoteStatic)
        let fallbackPrologue = Data(hex: fb.fallbackPrologue)

        // Step 1: Initiator sends IK message 1 with WRONG remote static
        let ikInitiator = HandshakeState(
            pattern: .IK,
            initiator: true,
            suite: suite,
            prologue: fallbackPrologue,
            s: try NoiseKeyPair(privateKeyData: initStatic),
            rs: wrongRemoteStatic,
            keyPairGenerator: DeterministicKeyPairGenerator(privateKeyData: initEphemeral)
        )
        let (ikMsg1, _) = try ikInitiator.writeMessage(
            payload: Data(hex: fb.ikMessage1.payload)
        )

        // Verify IK message 1 matches test vector
        XCTAssertEqual(ikMsg1.hex, fb.ikMessage1.ciphertext, "IK message 1 ciphertext mismatch")

        // Step 2: Responder extracts initiator ephemeral from IK msg 1
        let extractedEphemeral = Data(ikMsg1.prefix(DHLEN))
        XCTAssertEqual(extractedEphemeral, initEphPub)

        // Step 3: Set up XXfallback — responder becomes initiator
        let fallbackInitiator = HandshakeState(
            pattern: .XXfallback,
            initiator: true,
            suite: suite,
            prologue: fallbackPrologue,
            s: try NoiseKeyPair(privateKeyData: respStatic),
            re: extractedEphemeral,
            keyPairGenerator: DeterministicKeyPairGenerator(privateKeyData: respEphemeral)
        )

        // Step 4: Original initiator becomes XXfallback responder
        let fallbackResponder = HandshakeState(
            pattern: .XXfallback,
            initiator: false,
            suite: suite,
            prologue: fallbackPrologue,
            s: try NoiseKeyPair(privateKeyData: initStatic),
            e: try NoiseKeyPair(privateKeyData: initEphemeral),
            keyPairGenerator: SequentialKeyPairGenerator(keys: [])
        )

        // Message 2: fallback initiator writes
        let (fbMsg2, _) = try fallbackInitiator.writeMessage(
            payload: Data(hex: fb.fallbackMessages[0].payload)
        )
        XCTAssertEqual(fbMsg2.hex, fb.fallbackMessages[0].ciphertext, "XXfallback message 2 ciphertext mismatch")

        // Fallback responder reads message 2
        let (fbPayload2, _) = try fallbackResponder.readMessage(fbMsg2)
        XCTAssertEqual(fbPayload2, Data(hex: fb.fallbackMessages[0].payload))

        // Message 3: fallback responder writes
        let (fbMsg3, fbRespTransport) = try fallbackResponder.writeMessage(
            payload: Data(hex: fb.fallbackMessages[1].payload)
        )
        XCTAssertEqual(fbMsg3.hex, fb.fallbackMessages[1].ciphertext, "XXfallback message 3 ciphertext mismatch")

        // Fallback initiator reads message 3
        let (fbPayload3, fbInitTransport) = try fallbackInitiator.readMessage(fbMsg3)
        XCTAssertEqual(fbPayload3, Data(hex: fb.fallbackMessages[1].payload))

        // Both should have completed
        XCTAssertNotNil(fbRespTransport)
        XCTAssertNotNil(fbInitTransport)

        // Handshake hash
        XCTAssertEqual(fbInitTransport!.handshakeHash.hex, fb.handshakeHash)
        XCTAssertEqual(fbRespTransport!.handshakeHash.hex, fb.handshakeHash)

        // Transport message: initiator (original responder) sends
        let transportPayload = Data(hex: fb.transportMessage.payload)
        let transportCt = try fbInitTransport!.sendCipher.encryptWithAd(Data(), plaintext: transportPayload)
        XCTAssertEqual(transportCt.hex, fb.transportMessage.ciphertext, "XXfallback transport ciphertext mismatch")
    }

    // MARK: - Shared test runners

    /// Load all vectors for a given suite file and run each one.
    private func runAllVectors(fileName: String, suite: CipherSuite) throws {
        let vf = Self.loadVectorFile(fileName)
        for vector in vf.vectors {
            guard let pattern = Self.patternMap[vector.pattern] else {
                XCTFail("Unknown pattern '\(vector.pattern)' in \(fileName)")
                continue
            }
            let keys = vf.keys
            let handshakeMessages = vector.handshakeMessages.map {
                TestMessage(payload: Data(hex: $0.payload), ciphertext: Data(hex: $0.ciphertext))
            }
            let transportMessages = vector.transportMessages.map {
                TestMessage(payload: Data(hex: $0.payload), ciphertext: Data(hex: $0.ciphertext))
            }
            let psks = vector.psks.map { resolveKeyRequired($0, keys: keys) }

            try runHandshakeTest(
                suite: suite,
                keys: keys,
                pattern: pattern,
                initiatorStatic: resolveKey(vector.initStatic, keys: keys),
                responderStatic: resolveKey(vector.respStatic, keys: keys),
                initiatorRemoteStatic: resolveKey(vector.initRemoteStatic, keys: keys),
                responderRemoteStatic: resolveKey(vector.respRemoteStatic, keys: keys),
                psks: psks,
                handshakeMessages: handshakeMessages,
                transportMessages: transportMessages,
                expectedHandshakeHash: Data(hex: vector.handshakeHash),
                label: "\(fileName)/\(vector.pattern)"
            )
        }
    }

    private func runHandshakeTest(
        suite: CipherSuite,
        keys: [String: String],
        pattern: HandshakePattern,
        initiatorStatic: Data?,
        responderStatic: Data?,
        initiatorRemoteStatic: Data?,
        responderRemoteStatic: Data?,
        psks: [Data] = [],
        handshakeMessages: [TestMessage],
        transportMessages: [TestMessage],
        expectedHandshakeHash: Data,
        label: String = ""
    ) throws {
        let prologue = resolveKeyRequired("prologue", keys: keys)
        let initEphemeral = resolveKeyRequired("init_ephemeral", keys: keys)
        let respEphemeral = resolveKeyRequired("resp_ephemeral", keys: keys)

        let initS = try initiatorStatic.map { try NoiseKeyPair(privateKeyData: $0) }
        let respS = try responderStatic.map { try NoiseKeyPair(privateKeyData: $0) }

        let initiator = HandshakeState(
            pattern: pattern,
            initiator: true,
            suite: suite,
            prologue: prologue,
            s: initS,
            rs: initiatorRemoteStatic,
            psks: psks,
            keyPairGenerator: DeterministicKeyPairGenerator(privateKeyData: initEphemeral)
        )
        let responder = HandshakeState(
            pattern: pattern,
            initiator: false,
            suite: suite,
            prologue: prologue,
            s: respS,
            rs: responderRemoteStatic,
            psks: psks,
            keyPairGenerator: DeterministicKeyPairGenerator(privateKeyData: respEphemeral)
        )

        var initTransport: TransportState?
        var respTransport: TransportState?

        // Process handshake messages
        for (i, msg) in handshakeMessages.enumerated() {
            let isInitiatorSend = (i % 2 == 0)
            if isInitiatorSend {
                let (ct, transport) = try initiator.writeMessage(payload: msg.payload)
                XCTAssertEqual(ct.hex, msg.ciphertext.hex, "\(label) handshake msg \(i+1) ciphertext mismatch")
                if let t = transport { initTransport = t }

                let (payload, rTransport) = try responder.readMessage(ct)
                XCTAssertEqual(payload, msg.payload, "\(label) handshake msg \(i+1) payload mismatch")
                if let t = rTransport { respTransport = t }
            } else {
                let (ct, transport) = try responder.writeMessage(payload: msg.payload)
                XCTAssertEqual(ct.hex, msg.ciphertext.hex, "\(label) handshake msg \(i+1) ciphertext mismatch")
                if let t = transport { respTransport = t }

                let (payload, iTransport) = try initiator.readMessage(ct)
                XCTAssertEqual(payload, msg.payload, "\(label) handshake msg \(i+1) payload mismatch")
                if let t = iTransport { initTransport = t }
            }
        }

        // Verify handshake completed
        XCTAssertNotNil(initTransport, "\(label) initiator handshake did not complete")
        XCTAssertNotNil(respTransport, "\(label) responder handshake did not complete")

        // Verify handshake hash
        XCTAssertEqual(initTransport!.handshakeHash.hex, expectedHandshakeHash.hex, "\(label) initiator handshake hash mismatch")
        XCTAssertEqual(respTransport!.handshakeHash.hex, expectedHandshakeHash.hex, "\(label) responder handshake hash mismatch")

        // Process transport messages
        for (i, msg) in transportMessages.enumerated() {
            let isInitiatorSend = ((handshakeMessages.count + i) % 2 == 0)
            if isInitiatorSend {
                let ct = try initTransport!.sendCipher.encryptWithAd(Data(), plaintext: msg.payload)
                XCTAssertEqual(ct.hex, msg.ciphertext.hex, "\(label) transport msg \(i+1) ciphertext mismatch")
                let pt = try respTransport!.receiveCipher.decryptWithAd(Data(), ciphertext: ct)
                XCTAssertEqual(pt, msg.payload, "\(label) transport msg \(i+1) payload mismatch")
            } else {
                let ct = try respTransport!.sendCipher.encryptWithAd(Data(), plaintext: msg.payload)
                XCTAssertEqual(ct.hex, msg.ciphertext.hex, "\(label) transport msg \(i+1) ciphertext mismatch")
                let pt = try initTransport!.receiveCipher.decryptWithAd(Data(), ciphertext: ct)
                XCTAssertEqual(pt, msg.payload, "\(label) transport msg \(i+1) payload mismatch")
            }
        }
    }
}
