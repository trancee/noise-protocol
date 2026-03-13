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
}

// MARK: - Test Vector Tests

final class TestVectorTests: XCTestCase {

    // MARK: - JSON loading (once per test run)

    private static let vectorFile: VectorFile = {
        let testFileURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent() // → Tests/NoiseProtocolTests/
            .deletingLastPathComponent() // → Tests/
            .deletingLastPathComponent() // → ios/
            .deletingLastPathComponent() // → repo root
            .appendingPathComponent("test-vectors")
            .appendingPathComponent("noise_25519_ChaChaPoly_SHA256.json")
        let data = try! Data(contentsOf: testFileURL)
        return try! JSONDecoder().decode(VectorFile.self, from: data)
    }()

    private var keys: [String: String] { Self.vectorFile.keys }

    /// Resolve a key name reference from the JSON `keys` object to raw bytes.
    /// Returns `nil` when the key name is `nil` (JSON `null`).
    private func resolveKey(_ keyName: String?) -> Data? {
        guard let keyName = keyName, let hex = keys[keyName] else { return nil }
        return Data(hex: hex)
    }

    /// Resolve a key name that is expected to exist.
    private func resolveKeyRequired(_ keyName: String) -> Data {
        guard let hex = keys[keyName] else {
            fatalError("Key '\(keyName)' not found in test vector keys")
        }
        return Data(hex: hex)
    }

    private func vector(forPattern pattern: String) -> Vector {
        guard let v = Self.vectorFile.vectors.first(where: { $0.pattern == pattern }) else {
            fatalError("No test vector found for pattern '\(pattern)'")
        }
        return v
    }

    // MARK: NN

    func testNN() throws {
        try runVectorTest(forPattern: "NN", handshakePattern: .NN)
    }

    // MARK: NK

    func testNK() throws {
        try runVectorTest(forPattern: "NK", handshakePattern: .NK)
    }

    // MARK: XX

    func testXX() throws {
        try runVectorTest(forPattern: "XX", handshakePattern: .XX)
    }

    // MARK: IK

    func testIK() throws {
        try runVectorTest(forPattern: "IK", handshakePattern: .IK)
    }

    // MARK: NKpsk0

    func testNKpsk0() throws {
        try runVectorTest(forPattern: "NKpsk0", handshakePattern: .NKpsk0)
    }

    // MARK: IKpsk2

    func testIKpsk2() throws {
        try runVectorTest(forPattern: "IKpsk2", handshakePattern: .IKpsk2)
    }

    // MARK: XXfallback

    func testXXfallback() throws {
        let fb = Self.vectorFile.fallbackVectors[0]
        let initEphemeral = resolveKeyRequired("init_ephemeral")
        let respEphemeral = resolveKeyRequired("resp_ephemeral")
        let initStatic = resolveKeyRequired("init_static")
        let respStatic = resolveKeyRequired("resp_static")
        let initEphPub = resolveKeyRequired("init_eph_pub")
        let wrongRemoteStatic = Data(hex: fb.wrongRemoteStatic)
        let fallbackPrologue = Data(hex: fb.fallbackPrologue)

        // Step 1: Initiator sends IK message 1 with WRONG remote static
        let ikInitiator = HandshakeState(
            pattern: .IK,
            initiator: true,
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
            prologue: fallbackPrologue,
            s: try NoiseKeyPair(privateKeyData: respStatic),
            re: extractedEphemeral,
            keyPairGenerator: DeterministicKeyPairGenerator(privateKeyData: respEphemeral)
        )

        // Step 4: Original initiator becomes XXfallback responder
        let fallbackResponder = HandshakeState(
            pattern: .XXfallback,
            initiator: false,
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

    // MARK: - Shared handshake runner

    /// Convenience wrapper that resolves a JSON vector by pattern name and runs the handshake test.
    private func runVectorTest(forPattern patternName: String, handshakePattern: HandshakePattern) throws {
        let v = vector(forPattern: patternName)
        let handshakeMessages = v.handshakeMessages.map {
            TestMessage(payload: Data(hex: $0.payload), ciphertext: Data(hex: $0.ciphertext))
        }
        let transportMessages = v.transportMessages.map {
            TestMessage(payload: Data(hex: $0.payload), ciphertext: Data(hex: $0.ciphertext))
        }
        let psks = v.psks.map { resolveKeyRequired($0) }

        try runHandshakeTest(
            pattern: handshakePattern,
            initiatorStatic: resolveKey(v.initStatic),
            responderStatic: resolveKey(v.respStatic),
            initiatorRemoteStatic: resolveKey(v.initRemoteStatic),
            responderRemoteStatic: resolveKey(v.respRemoteStatic),
            psks: psks,
            handshakeMessages: handshakeMessages,
            transportMessages: transportMessages,
            expectedHandshakeHash: Data(hex: v.handshakeHash)
        )
    }

    private func runHandshakeTest(
        pattern: HandshakePattern,
        initiatorStatic: Data?,
        responderStatic: Data?,
        initiatorRemoteStatic: Data?,
        responderRemoteStatic: Data?,
        psks: [Data] = [],
        handshakeMessages: [TestMessage],
        transportMessages: [TestMessage],
        expectedHandshakeHash: Data
    ) throws {
        let prologue = resolveKeyRequired("prologue")
        let initEphemeral = resolveKeyRequired("init_ephemeral")
        let respEphemeral = resolveKeyRequired("resp_ephemeral")

        let initS = try initiatorStatic.map { try NoiseKeyPair(privateKeyData: $0) }
        let respS = try responderStatic.map { try NoiseKeyPair(privateKeyData: $0) }

        let initiator = HandshakeState(
            pattern: pattern,
            initiator: true,
            prologue: prologue,
            s: initS,
            rs: initiatorRemoteStatic,
            psks: psks,
            keyPairGenerator: DeterministicKeyPairGenerator(privateKeyData: initEphemeral)
        )
        let responder = HandshakeState(
            pattern: pattern,
            initiator: false,
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
                XCTAssertEqual(ct.hex, msg.ciphertext.hex, "Handshake msg \(i+1) ciphertext mismatch")
                if let t = transport { initTransport = t }

                let (payload, rTransport) = try responder.readMessage(ct)
                XCTAssertEqual(payload, msg.payload, "Handshake msg \(i+1) payload mismatch")
                if let t = rTransport { respTransport = t }
            } else {
                let (ct, transport) = try responder.writeMessage(payload: msg.payload)
                XCTAssertEqual(ct.hex, msg.ciphertext.hex, "Handshake msg \(i+1) ciphertext mismatch")
                if let t = transport { respTransport = t }

                let (payload, iTransport) = try initiator.readMessage(ct)
                XCTAssertEqual(payload, msg.payload, "Handshake msg \(i+1) payload mismatch")
                if let t = iTransport { initTransport = t }
            }
        }

        // Verify handshake completed
        XCTAssertNotNil(initTransport, "Initiator handshake did not complete")
        XCTAssertNotNil(respTransport, "Responder handshake did not complete")

        // Verify handshake hash
        XCTAssertEqual(initTransport!.handshakeHash.hex, expectedHandshakeHash.hex, "Initiator handshake hash mismatch")
        XCTAssertEqual(respTransport!.handshakeHash.hex, expectedHandshakeHash.hex, "Responder handshake hash mismatch")

        // Process transport messages
        for (i, msg) in transportMessages.enumerated() {
            let isInitiatorSend = ((handshakeMessages.count + i) % 2 == 0)
            if isInitiatorSend {
                let ct = try initTransport!.sendCipher.encryptWithAd(Data(), plaintext: msg.payload)
                XCTAssertEqual(ct.hex, msg.ciphertext.hex, "Transport msg \(i+1) ciphertext mismatch")
                let pt = try respTransport!.receiveCipher.decryptWithAd(Data(), ciphertext: ct)
                XCTAssertEqual(pt, msg.payload, "Transport msg \(i+1) payload mismatch")
            } else {
                let ct = try respTransport!.sendCipher.encryptWithAd(Data(), plaintext: msg.payload)
                XCTAssertEqual(ct.hex, msg.ciphertext.hex, "Transport msg \(i+1) ciphertext mismatch")
                let pt = try initTransport!.receiveCipher.decryptWithAd(Data(), ciphertext: ct)
                XCTAssertEqual(pt, msg.payload, "Transport msg \(i+1) payload mismatch")
            }
        }
    }
}
