import CryptoKit
import Foundation
import NoiseCore

private struct OfficialNoiseVectorDocument: Decodable {
    let vectors: [OfficialNoiseVector]
}

private struct OfficialNoiseVector: Decodable {
    let protocolName: String
    let initPrologue: String
    let initStatic: String?
    let initEphemeral: String?
    let initRemoteStatic: String?
    let respPrologue: String
    let respStatic: String?
    let respEphemeral: String?
    let respRemoteStatic: String?
    let handshakeHash: String?
    let messages: [OfficialNoiseVectorMessage]
    let fail: Bool?
    let fallback: Bool?
    let hybrid: String?
    let initPsks: [String]?
    let respPsks: [String]?
    let initPsk: String?
    let respPsk: String?
    let name: String?

    enum CodingKeys: String, CodingKey {
        case protocolName = "protocol_name"
        case initPrologue = "init_prologue"
        case initStatic = "init_static"
        case initEphemeral = "init_ephemeral"
        case initRemoteStatic = "init_remote_static"
        case respPrologue = "resp_prologue"
        case respStatic = "resp_static"
        case respEphemeral = "resp_ephemeral"
        case respRemoteStatic = "resp_remote_static"
        case handshakeHash = "handshake_hash"
        case messages
        case fail
        case fallback
        case hybrid
        case initPsks = "init_psks"
        case respPsks = "resp_psks"
        case initPsk = "init_psk"
        case respPsk = "resp_psk"
        case name
    }
}

private struct OfficialNoiseVectorMessage: Decodable {
    let payload: String
    let ciphertext: String
}

private struct PersistedNoiseVectorFixture: Encodable {
    let schema: String
    let fixture: NoiseVectorFixture

    enum CodingKeys: String, CodingKey {
        case schema = "$schema"
        case schemaVersion = "schema_version"
        case vectorID = "vector_id"
        case description
        case protocolInfo = "protocol"
        case inputs
        case expected
        case negativeCases = "negative_cases"
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schema, forKey: .schema)
        try container.encode(fixture.schemaVersion, forKey: .schemaVersion)
        try container.encode(fixture.vectorID, forKey: .vectorID)
        try container.encodeIfPresent(fixture.description, forKey: .description)
        try container.encode(fixture.protocolInfo, forKey: .protocolInfo)
        try container.encode(fixture.inputs, forKey: .inputs)
        try container.encode(fixture.expected, forKey: .expected)
        try container.encode(fixture.negativeCases, forKey: .negativeCases)
    }
}

public struct NoiseVectorFixtureWriter: Sendable {
    public static let defaultSchemaPath = "../../schema/noise-vector-v1.schema.json"

    public init() {}

    public func serialize(
        _ fixture: NoiseVectorFixture,
        schemaPath: String = Self.defaultSchemaPath
    ) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(PersistedNoiseVectorFixture(schema: schemaPath, fixture: fixture))
        guard let string = String(data: data, encoding: .utf8) else {
            throw NoiseTestHarnessError.invalidFixture("Unable to encode fixture JSON as UTF-8.")
        }
        return string + "\n"
    }

    @discardableResult
    public func write(
        _ fixture: NoiseVectorFixture,
        to url: URL,
        schemaPath: String = Self.defaultSchemaPath
    ) throws -> URL {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try serialize(fixture, schemaPath: schemaPath).write(to: url, atomically: true, encoding: .utf8)
        return url
    }
}

public struct OfficialNoiseVectorConverter: Sendable {
    public static let defaultSchemaPath = "../../schema/noise-vector-v1.schema.json"

    private let runner: NoiseVectorRunner
    private let writer: NoiseVectorFixtureWriter

    public init(
        runner: NoiseVectorRunner = NoiseVectorRunner(),
        writer: NoiseVectorFixtureWriter = NoiseVectorFixtureWriter()
    ) {
        self.runner = runner
        self.writer = writer
    }

    public func convertDocument(_ document: String) async throws -> [NoiseVectorFixture] {
        let officialDocument = try JSONDecoder().decode(OfficialNoiseVectorDocument.self, from: Data(document.utf8))
        var assignedIDs: [String: Int] = [:]
        var fixtures: [NoiseVectorFixture] = []
        fixtures.reserveCapacity(officialDocument.vectors.count)

        for (index, vector) in officialDocument.vectors.enumerated() {
            let baseID = defaultVectorID(vector: vector, index: index)
            let occurrence = (assignedIDs[baseID] ?? 0) + 1
            assignedIDs[baseID] = occurrence
            let vectorID = occurrence == 1 ? baseID : "\(baseID)-\(occurrence)"
            fixtures.append(try await convert(vector: vector, vectorID: vectorID))
        }

        return fixtures
    }

    public func convertDocument(
        _ document: String,
        outputDirectory: URL,
        schemaPath: String = Self.defaultSchemaPath
    ) async throws -> [URL] {
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        let fixtures = try await convertDocument(document)
        return try fixtures.map { fixture in
            try writer.write(
                fixture,
                to: outputDirectory.appendingPathComponent("\(fixture.vectorID).json"),
                schemaPath: schemaPath
            )
        }
    }

    private func convert(vector: OfficialNoiseVector, vectorID: String) async throws -> NoiseVectorFixture {
        guard vector.fail != true else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise vectors marked fail=true cannot be translated into passing shared fixtures."
            )
        }
        guard vector.fallback != true else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise fallback vectors are not representable by the shared v1 fixture contract."
            )
        }
        guard vector.hybrid == nil else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise hybrid vectors are not representable by the shared v1 fixture contract."
            )
        }
        guard vector.initPrologue.caseInsensitiveCompare(vector.respPrologue) == .orderedSame else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise vectors with asymmetric initiator/responder prologues are not representable by the shared v1 fixture contract."
            )
        }

        let descriptor = try parseProtocolDescriptor(vector.protocolName)
        let initiatorStatic = try resolveKeyPair(hexPrivateKey: vector.initStatic, fallbackSeed: 0x11)
        let initiatorEphemeral = try resolveKeyPair(hexPrivateKey: vector.initEphemeral, fallbackSeed: 0x21)
        let responderStatic = try resolveKeyPair(hexPrivateKey: vector.respStatic, fallbackSeed: 0x31)
        let responderEphemeral = try resolveKeyPair(hexPrivateKey: vector.respEphemeral, fallbackSeed: 0x41)

        if let initRemoteStatic = vector.initRemoteStatic {
            let expected = try Data(noiseHex: initRemoteStatic)
            guard expected == responderStatic.publicKey else {
                throw NoiseTestHarnessError.invalidFixture(
                    "Official init_remote_static does not match the responder static public key derived for \(vector.protocolName)."
                )
            }
        }
        if let respRemoteStatic = vector.respRemoteStatic {
            let expected = try Data(noiseHex: respRemoteStatic)
            guard expected == initiatorStatic.publicKey else {
                throw NoiseTestHarnessError.invalidFixture(
                    "Official resp_remote_static does not match the initiator static public key derived for \(vector.protocolName)."
                )
            }
        }

        let initiatorPsks = vector.initPsks ?? (vector.initPsk.map { [$0] } ?? [])
        let responderPsks = vector.respPsks ?? (vector.respPsk.map { [$0] } ?? [])
        guard initiatorPsks.count == responderPsks.count else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise PSK arrays must match for both parties to translate into the shared v1 fixture contract."
            )
        }
        guard zip(initiatorPsks, responderPsks).allSatisfy({ $0.0.caseInsensitiveCompare($0.1) == .orderedSame }) else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise PSK arrays differ between initiator and responder; shared v1 fixtures store a single agreed PSK set."
            )
        }
        guard initiatorPsks.count == descriptor.pskPlacements.count else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise vector PSK count \(initiatorPsks.count) does not match protocol placements \(descriptor.pskPlacements.count) for \(vector.protocolName)."
            )
        }

        let preSharedKeys = try Dictionary(uniqueKeysWithValues: zip(descriptor.pskPlacements.sorted(), initiatorPsks).map {
            ("psk\($0)", try Data(noiseHex: $1).noiseHexString)
        })

        guard vector.messages.count >= descriptor.handshakeMessages.count else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise vector provides \(vector.messages.count) messages, but \(vector.protocolName) requires \(descriptor.handshakeMessages.count) handshake messages."
            )
        }

        let payloadInputs = try vector.messages.prefix(descriptor.handshakeMessages.count).enumerated().map { index, message in
            NoiseVectorPayloadInput(
                index: index,
                sender: descriptor.handshakeMessages[index].sender,
                plaintextHex: try Data(noiseHex: message.payload).noiseHexString
            )
        }

        let pendingFixture = NoiseVectorFixture(
            schemaVersion: "1.0.0",
            vectorID: vectorID,
            description: buildDescription(for: vector),
            protocolInfo: NoiseVectorProtocol(
                name: vector.protocolName,
                pattern: descriptor.pattern,
                suite: descriptor.suite
            ),
            inputs: NoiseVectorInputs(
                prologue: try Data(noiseHex: vector.initPrologue).noiseHexString,
                keyMaterial: NoiseVectorKeyMaterial(
                    initiator: NoiseVectorPartyKeyMaterial(
                        static: initiatorStatic.asFixtureKeyPair(),
                        ephemeral: initiatorEphemeral.asFixtureKeyPair()
                    ),
                    responder: NoiseVectorPartyKeyMaterial(
                        static: responderStatic.asFixtureKeyPair(),
                        ephemeral: responderEphemeral.asFixtureKeyPair()
                    )
                ),
                preSharedKeys: preSharedKeys.isEmpty ? nil : preSharedKeys,
                payloads: payloadInputs
            ),
            expected: NoiseVectorExpected(
                handshakeMessages: [],
                handshakeHash: "",
                splitTransportKeys: NoiseVectorExpectedSplitTransportKeys(
                    initiator: NoiseVectorExpectedTransportPartyKeys(tx: "", rx: ""),
                    responder: NoiseVectorExpectedTransportPartyKeys(tx: "", rx: "")
                )
            ),
            negativeCases: []
        )

        let executionResult = try await runner.execute(pendingFixture)

        for (index, message) in executionResult.handshakeMessages.sorted(by: { $0.index < $1.index }).enumerated() {
            let framed = try NoiseHandshakeMessage(encoded: Data(noiseHex: message.messageHex))
            let raw = framed.rawNoiseBytes.noiseHexString
            let expectedRaw = try Data(noiseHex: vector.messages[index].ciphertext).noiseHexString
            guard raw.caseInsensitiveCompare(expectedRaw) == .orderedSame else {
                throw NoiseTestHarnessError.invalidFixture(
                    "Translated official Noise vector handshake message \(index) for \(vector.protocolName) does not match the official ciphertext."
                )
            }
        }

        if let expectedHandshakeHash = vector.handshakeHash {
            let normalized = try Data(noiseHex: expectedHandshakeHash).noiseHexString
            guard executionResult.handshakeHashHex.caseInsensitiveCompare(normalized) == .orderedSame else {
                throw NoiseTestHarnessError.invalidFixture(
                    "Translated official Noise vector handshake hash for \(vector.protocolName) does not match the official handshake_hash."
                )
            }
        }

        return NoiseVectorFixture(
            schemaVersion: pendingFixture.schemaVersion,
            vectorID: pendingFixture.vectorID,
            description: pendingFixture.description,
            protocolInfo: pendingFixture.protocolInfo,
            inputs: pendingFixture.inputs,
            expected: NoiseVectorExpected(
                handshakeMessages: executionResult.handshakeMessages.map {
                    NoiseVectorExpectedHandshakeMessage(index: $0.index, sender: $0.sender, messageHex: $0.messageHex)
                },
                handshakeHash: executionResult.handshakeHashHex,
                splitTransportKeys: NoiseVectorExpectedSplitTransportKeys(
                    initiator: NoiseVectorExpectedTransportPartyKeys(
                        tx: executionResult.splitTransportKeys.initiator.txHex,
                        rx: executionResult.splitTransportKeys.initiator.rxHex
                    ),
                    responder: NoiseVectorExpectedTransportPartyKeys(
                        tx: executionResult.splitTransportKeys.responder.txHex,
                        rx: executionResult.splitTransportKeys.responder.rxHex
                    )
                )
            ),
            negativeCases: defaultNegativeCases(handshakeMessageCount: descriptor.handshakeMessages.count)
        )
    }

    private func resolveKeyPair(hexPrivateKey: String?, fallbackSeed: UInt8) throws -> NoiseDHKeyPair {
        let privateKey = try hexPrivateKey.map { try Data(noiseHex: $0) } ?? Data((0..<32).map { UInt8((Int(fallbackSeed) + $0) & 0xFF) })
        guard privateKey.count == 32 else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise vector field has invalid length for the selected DH algorithm."
            )
        }
        let cryptoKitKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        return NoiseDHKeyPair(
            privateKey: cryptoKitKey.rawRepresentation,
            publicKey: cryptoKitKey.publicKey.rawRepresentation
        )
    }

    private func parseProtocolDescriptor(_ protocolName: String) throws -> ParsedProtocolDescriptor {
        let parts = protocolName.split(separator: "_").map(String.init)
        guard parts.count == 5, parts.first == "Noise" else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise protocol name '\(protocolName)' is not in the expected Noise_<pattern>_<dh>_<cipher>_<hash> format."
            )
        }

        let patternSegment = parts[1]
        let patternExpression = try NSRegularExpression(pattern: "^([A-Z]+)((?:psk\\d+)?(?:\\+psk\\d+)*)$")
        let patternRange = NSRange(patternSegment.startIndex..<patternSegment.endIndex, in: patternSegment)
        guard let patternMatch = patternExpression.firstMatch(in: patternSegment, range: patternRange),
              patternMatch.range == patternRange,
              let basePatternRange = Range(patternMatch.range(at: 1), in: patternSegment),
              let modifiersRange = Range(patternMatch.range(at: 2), in: patternSegment)
        else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise protocol name '\(protocolName)' uses unsupported handshake pattern modifiers."
            )
        }

        let basePatternName = String(patternSegment[basePatternRange])
        let modifiers = String(patternSegment[modifiersRange])
        guard let handshakePatternName = NoiseHandshakePatternName(rawValue: basePatternName) else {
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise protocol name '\(protocolName)' uses unsupported handshake pattern '\(basePatternName)'."
            )
        }

        let definition = NoiseHandshakePatterns.pattern(named: handshakePatternName)
        let pskExpression = try NSRegularExpression(pattern: "psk(\\d+)")
        let modifiersRangeNS = NSRange(modifiers.startIndex..<modifiers.endIndex, in: modifiers)
        let matches = pskExpression.matches(in: modifiers, range: modifiersRangeNS)
        var placements: [Int] = []
        placements.reserveCapacity(matches.count)
        for match in matches {
            guard let range = Range(match.range(at: 1), in: modifiers),
                  let placement = Int(modifiers[range])
            else {
                continue
            }
            placements.append(placement)
        }
        guard Set(placements).count == placements.count else {
            throw NoiseTestHarnessError.invalidFixture("Official Noise protocol name '\(protocolName)' contains duplicate pskN modifiers.")
        }
        guard placements.allSatisfy({ $0 >= 0 && $0 <= definition.messages.count }) else {
            throw NoiseTestHarnessError.invalidFixture("Official Noise protocol name '\(protocolName)' contains unsupported pskN placements.")
        }

        let pattern: NoiseVectorPattern
        switch basePatternName {
        case "NN": pattern = .NN
        case "NK": pattern = .NK
        case "KK": pattern = .KK
        case "IK": pattern = .IK
        case "XX": pattern = .XX
        default:
            throw NoiseTestHarnessError.invalidFixture(
                "Official Noise protocol name '\(protocolName)' uses unsupported handshake pattern '\(basePatternName)'."
            )
        }

        guard parts[2] == "25519" else {
            throw NoiseTestHarnessError.invalidFixture("Unsupported official Noise DH algorithm '\(parts[2])'.")
        }

        let cipher: NoiseVectorCipher
        switch parts[3] {
        case "ChaChaPoly": cipher = .chaChaPoly
        case "AESGCM": cipher = .aesGCM
        default: throw NoiseTestHarnessError.invalidFixture("Unsupported official Noise cipher '\(parts[3])'.")
        }

        let hash: NoiseVectorHash
        switch parts[4] {
        case "SHA256": hash = .sha256
        case "SHA512": hash = .sha512
        case "BLAKE2s": hash = .blake2s
        case "BLAKE2b": hash = .blake2b
        default: throw NoiseTestHarnessError.invalidFixture("Unsupported official Noise hash '\(parts[4])'.")
        }

        var messages: [ParsedMessage] = []
        messages.reserveCapacity(definition.messages.count)
        for (index, message) in definition.messages.enumerated() {
            let sender: NoiseVectorSender = message.direction == .initiatorToResponder ? .initiator : .responder
            let keyPayloadCount = message.tokens.reduce(into: 0) { count, token in
                if token == .e || token == .s {
                    count += 1
                }
            }
            messages.append(ParsedMessage(index: index, sender: sender, keyPayloadCount: keyPayloadCount))
        }

        return ParsedProtocolDescriptor(
            pattern: pattern,
            suite: NoiseVectorSuite(dh: .x25519, cipher: cipher, hash: hash),
            pskPlacements: Set(placements),
            handshakeMessages: messages
        )
    }

    private func defaultVectorID(vector: OfficialNoiseVector, index: Int) -> String {
        let base = normalizeIdentifier(vector.protocolName)
        if let name = vector.name, name != vector.protocolName {
            let normalizedName = normalizeIdentifier(name)
            return normalizedName.isEmpty ? base : "\(base)-\(normalizedName)"
        }
        return base.isEmpty ? "official-noise-vector-\(index + 1)" : base
    }

    private func buildDescription(for vector: OfficialNoiseVector) -> String {
        if let name = vector.name, name != vector.protocolName {
            return "Imported from official Noise wiki vector '\(name)'."
        }
        return "Imported from the official Noise wiki vector for \(vector.protocolName)."
    }

    private func normalizeIdentifier(_ value: String) -> String {
        value.lowercased()
            .replacingOccurrences(of: "[^a-z0-9]+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    }

    private func defaultNegativeCases(handshakeMessageCount: Int) -> [NoiseVectorNegativeCase] {
        var cases = [
            NoiseVectorNegativeCase(
                id: "flip-tag-final-message",
                description: "Flip one bit in the final authentication tag on the last handshake message.",
                phase: .handshake,
                messageIndex: handshakeMessageCount - 1,
                mutation: NoiseVectorMutation(target: .tag, operation: "flip_last_bit"),
                expectedError: NoiseVectorExpectedError(
                    code: "decrypt_failed",
                    detail: "Handshake must abort and clear transient state."
                )
            )
        ]

        if handshakeMessageCount > 1 {
            cases.append(
                NoiseVectorNegativeCase(
                    id: "reorder-handshake-messages",
                    description: "Deliver message index 1 before message index 0.",
                    phase: .handshake,
                    messageIndex: nil,
                    mutation: NoiseVectorMutation(target: .messageOrder, operation: "swap_0_1"),
                    expectedError: NoiseVectorExpectedError(
                        code: "unexpected_message_order",
                        detail: "Implementation must reject out-of-order handshake traffic."
                    )
                )
            )
        }

        return cases
    }
}

private struct ParsedProtocolDescriptor {
    let pattern: NoiseVectorPattern
    let suite: NoiseVectorSuite
    let pskPlacements: Set<Int>
    let handshakeMessages: [ParsedMessage]
}

private struct ParsedMessage {
    let index: Int
    let sender: NoiseVectorSender
    let keyPayloadCount: Int
}

private extension NoiseDHKeyPair {
    func asFixtureKeyPair() -> NoiseVectorKeyPair {
        NoiseVectorKeyPair(private: privateKey.noiseHexString, public: publicKey.noiseHexString)
    }
}

private extension NoiseHandshakeMessage {
    var rawNoiseBytes: Data {
        var data = Data()
        for payload in keyPayloads {
            data.append(payload)
        }
        data.append(payload)
        return data
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
            guard let value = UInt8(byteString, radix: 16) else {
                throw NoiseTestHarnessError.invalidHex(rawHex)
            }
            data.append(value)
            index = nextIndex
        }

        self = data
    }

    var noiseHexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}