import Foundation
import Testing
import NoiseCore
@testable import NoiseTestHarness

@Test("iOS converts official NN vector into shared fixture artifacts")
func iosConvertsOfficialNnVectorIntoSharedFixtureArtifacts() async throws {
    let converter = OfficialNoiseVectorConverter()

    let fixtures = try await converter.convertDocument(officialNoiseNNDocument)

    #expect(fixtures.count == 1)
    let fixture = try #require(fixtures.first)
    #expect(fixture.vectorID == "noise-nn-25519-chachapoly-sha256")
    #expect(fixture.protocolInfo.name == "Noise_NN_25519_ChaChaPoly_SHA256")
    #expect(fixture.expected.handshakeMessages.count == 2)

    let result = try await NoiseVectorRunner().verifyExpected(fixture)
    #expect(result.handshakeHashHex.lowercased() == fixture.expected.handshakeHash.lowercased())
}

@Test("iOS persists converted official vector as shared fixture JSON")
func iosPersistsConvertedOfficialVectorAsSharedFixtureJSON() async throws {
    let converter = OfficialNoiseVectorConverter()
    let outputDirectory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)

    let urls = try await converter.convertDocument(officialNoiseNNDocument, outputDirectory: outputDirectory)

    #expect(urls.count == 1)
    let url = try #require(urls.first)
    let loader = NoiseVectorFixtureLoader(fixturesDirectory: outputDirectory)
    let fixture = try loader.loadFixture(fileName: url.lastPathComponent)
    #expect(fixture.vectorID == "noise-nn-25519-chachapoly-sha256")
}

  @Test("iOS converts official NNpsk0 vector into equivalent shared fixture artifacts")
  func iosConvertsOfficialNnpsk0VectorIntoEquivalentSharedFixtureArtifacts() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-nnpsk0-25519-chachapoly-sha256.json")
    let converter = OfficialNoiseVectorConverter()

    let converted = try await converter.convertDocument(
      officialDocument(
        from: fixture,
        initiatorPskField: "init_psk",
        responderPskField: "resp_psk"
      )
    )

    let actual = try #require(converted.first)
    assertEquivalentFixtureArtifacts(expected: fixture, actual: actual)
  }

  @Test("iOS converts official XXpsk2 vector with plural PSK fields into equivalent shared fixture artifacts")
  func iosConvertsOfficialXxpsk2VectorIntoEquivalentSharedFixtureArtifacts() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-xxpsk2-25519-chachapoly-sha256.json")
    let converter = OfficialNoiseVectorConverter()

    let converted = try await converter.convertDocument(
      officialDocument(
        from: fixture,
        initiatorPskField: "init_psks",
        responderPskField: "resp_psks"
      )
    )

    let actual = try #require(converted.first)
    assertEquivalentFixtureArtifacts(expected: fixture, actual: actual)
  }

  @Test("iOS converts official NN 448 vector into equivalent shared fixture artifacts")
  func iosConvertsOfficialNn448VectorIntoEquivalentSharedFixtureArtifacts() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-nn-448-chachapoly-sha256.json")
    let converter = OfficialNoiseVectorConverter()

    let converted = try await converter.convertDocument(
      officialDocument(
        from: fixture,
        initiatorPskField: "init_psks",
        responderPskField: "resp_psks"
      )
    )

    let actual = try #require(converted.first)
    assertEquivalentFixtureArtifacts(expected: fixture, actual: actual)
  }

  @Test("iOS converts official NN BLAKE2s vector into equivalent shared fixture artifacts")
  func iosConvertsOfficialNnBlake2sVectorIntoEquivalentSharedFixtureArtifacts() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-nn-25519-chachapoly-blake2s.json")
    let converter = OfficialNoiseVectorConverter()

    let converted = try await converter.convertDocument(
      officialDocument(
        from: fixture,
        initiatorPskField: "init_psk",
        responderPskField: "resp_psk"
      )
    )

    let actual = try #require(converted.first)
    assertEquivalentFixtureArtifacts(expected: fixture, actual: actual)
  }

@Test("iOS official vector converter rejects unsupported fallback vectors")
func iosOfficialVectorConverterRejectsFallbackVectors() async throws {
    await assertInvalidFixture(
      officialNoiseFallbackDocument,
      expectedMessage: "Official Noise fallback vectors are not representable by the shared v1 fixture contract."
    )
}

@Test("iOS official vector converter rejects unsupported hybrid vectors")
func iosOfficialVectorConverterRejectsHybridVectors() async throws {
    await assertInvalidFixture(
      officialNoiseHybridDocument,
      expectedMessage: "Official Noise hybrid vectors are not representable by the shared v1 fixture contract."
    )
}

@Test("iOS official vector converter rejects asymmetric prologue vectors")
func iosOfficialVectorConverterRejectsAsymmetricPrologueVectors() async throws {
    await assertInvalidFixture(
      officialNoiseAsymmetricPrologueDocument,
      expectedMessage: "Official Noise vectors with asymmetric initiator/responder prologues are not representable by the shared v1 fixture contract."
    )
}

@Test("iOS official vector converter rejects mismatched PSK values")
func iosOfficialVectorConverterRejectsMismatchedPskValues() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-nnpsk0-25519-chachapoly-sha256.json")
    let document = officialDocument(
      from: fixture,
      initiatorPskField: "init_psk",
      responderPskField: "resp_psk"
    ).replacingOccurrences(
      of: "\"resp_psk\": \"00112233445566778899aabbccddeefffedcba98765432100123456789abcdef\"",
      with: "\"resp_psk\": \"ff112233445566778899aabbccddeefffedcba98765432100123456789abcdef\""
    )

    await assertInvalidFixture(
      document,
      expectedMessage: "Official Noise PSK arrays differ between initiator and responder; shared v1 fixtures store a single agreed PSK set."
    )
}

@Test("iOS official vector converter rejects mismatched PSK counts")
func iosOfficialVectorConverterRejectsMismatchedPskCounts() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-xxpsk2-25519-chachapoly-sha256.json")
    let psk = fixture.inputs.preSharedKeys?["psk2"]?.lowercased() ?? ""
    let document = officialDocument(
      from: fixture,
      initiatorPskField: "init_psks",
      responderPskField: "resp_psks"
    ).replacingOccurrences(
      of: "\"resp_psks\": [\"\(psk)\"]",
      with: "\"resp_psks\": []"
    )

    await assertInvalidFixture(
      document,
      expectedMessage: "Official Noise PSK arrays must match for both parties to translate into the shared v1 fixture contract."
    )
}

@Test("iOS official vector converter rejects mismatched init_remote_static values")
func iosOfficialVectorConverterRejectsMismatchedInitRemoteStatic() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-xxpsk2-25519-chachapoly-sha256.json")
    let responderEphemeral = fixture.inputs.keyMaterial.responder.ephemeral.private.lowercased()
    let responderPublic = fixture.inputs.keyMaterial.responder.static.public.lowercased()
    let document = officialDocument(
      from: fixture,
      initiatorPskField: "init_psks",
      responderPskField: "resp_psks"
    ).replacingOccurrences(
      of: "\"resp_ephemeral\": \"\(responderEphemeral)\",",
      with: "\"resp_ephemeral\": \"\(responderEphemeral)\",\n      \"init_remote_static\": \"\(mutateHex(responderPublic))\","
    )

    await assertInvalidFixture(
      document,
      expectedMessage: "Official init_remote_static does not match the responder static public key derived for Noise_XXpsk2_25519_ChaChaPoly_SHA256."
    )
}

@Test("iOS official vector converter rejects mismatched resp_remote_static values")
func iosOfficialVectorConverterRejectsMismatchedRespRemoteStatic() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-xxpsk2-25519-chachapoly-sha256.json")
    let responderEphemeral = fixture.inputs.keyMaterial.responder.ephemeral.private.lowercased()
    let initiatorPublic = fixture.inputs.keyMaterial.initiator.static.public.lowercased()
    let document = officialDocument(
      from: fixture,
      initiatorPskField: "init_psks",
      responderPskField: "resp_psks"
    ).replacingOccurrences(
      of: "\"resp_ephemeral\": \"\(responderEphemeral)\",",
      with: "\"resp_ephemeral\": \"\(responderEphemeral)\",\n      \"resp_remote_static\": \"\(mutateHex(initiatorPublic))\","
    )

    await assertInvalidFixture(
      document,
      expectedMessage: "Official resp_remote_static does not match the initiator static public key derived for Noise_XXpsk2_25519_ChaChaPoly_SHA256."
    )
}

@Test("iOS official vector converter rejects mismatched handshake ciphertext")
func iosOfficialVectorConverterRejectsMismatchedHandshakeCiphertext() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-xxpsk2-25519-chachapoly-sha256.json")
    let originalCiphertext = fixture.expected.handshakeMessages
      .sorted { $0.index < $1.index }[1]
      .messageHex
    let document = officialDocument(
      from: fixture,
      initiatorPskField: "init_psks",
      responderPskField: "resp_psks"
    ).replacingOccurrences(
      of: rawCiphertextHex(fromEncodedMessageHex: originalCiphertext),
      with: mutateHex(rawCiphertextHex(fromEncodedMessageHex: originalCiphertext))
    )

    await assertInvalidFixture(
      document,
      expectedMessage: "Translated official Noise vector handshake message 1 for Noise_XXpsk2_25519_ChaChaPoly_SHA256 does not match the official ciphertext."
    )
}

@Test("iOS official vector converter rejects mismatched handshake hash")
func iosOfficialVectorConverterRejectsMismatchedHandshakeHash() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-xxpsk2-25519-chachapoly-sha256.json")
    let handshakeHash = fixture.expected.handshakeHash.lowercased()
    let document = officialDocument(
      from: fixture,
      initiatorPskField: "init_psks",
      responderPskField: "resp_psks"
    ).replacingOccurrences(
      of: "\"handshake_hash\": \"\(handshakeHash)\"",
      with: "\"handshake_hash\": \"\(mutateHex(handshakeHash))\""
    )

    await assertInvalidFixture(
      document,
      expectedMessage: "Translated official Noise vector handshake hash for Noise_XXpsk2_25519_ChaChaPoly_SHA256 does not match the official handshake_hash."
    )
}

private let officialNoiseNNDocument = """
{
  "vectors": [
    {
      "protocol_name": "Noise_NN_25519_ChaChaPoly_SHA256",
      "init_prologue": "50726f6c6f6775652d7631",
      "init_static": null,
      "init_ephemeral": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
      "resp_prologue": "50726f6c6f6775652d7631",
      "resp_static": null,
      "resp_ephemeral": "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
      "handshake_hash": "0cdc4eae809d187a4750de10df59c29e4a026edf95727efaeb18b569ebf9bf8f",
      "messages": [
        {
          "payload": "48656c6c6f",
          "ciphertext": "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a48656c6c6f"
        },
        {
          "payload": "776f726c64",
          "ciphertext": "dc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d448aa2198ed1ac9d712e7cfb5f3cc5e3202652d8e6d8"
        }
      ]
    }
  ]
}
"""

private let officialNoiseFallbackDocument = """
{
  "vectors": [
    {
      "protocol_name": "Noise_IK_25519_ChaChaPoly_SHA256",
      "fallback": true,
      "init_prologue": "00",
      "resp_prologue": "00",
      "messages": [
        {
          "payload": "",
          "ciphertext": ""
        }
      ]
    }
  ]
}
"""

private let officialNoiseHybridDocument = """
{
  "vectors": [
    {
      "protocol_name": "Noise_NN_25519_ChaChaPoly_SHA256",
      "hybrid": "Kyber1024",
      "init_prologue": "00",
      "resp_prologue": "00",
      "messages": [
        {
          "payload": "",
          "ciphertext": ""
        }
      ]
    }
  ]
}
"""

private let officialNoiseAsymmetricPrologueDocument = """
{
  "vectors": [
    {
      "protocol_name": "Noise_NN_25519_ChaChaPoly_SHA256",
      "init_prologue": "00",
      "resp_prologue": "ff",
      "messages": [
        {
          "payload": "",
          "ciphertext": ""
        }
      ]
    }
  ]
}
"""

private func assertEquivalentFixtureArtifacts(expected: NoiseVectorFixture, actual: NoiseVectorFixture) {
  #expect(actual.vectorID == expected.vectorID)
  #expect(actual.protocolInfo == expected.protocolInfo)
  #expect(actual.inputs.prologue.lowercased() == expected.inputs.prologue.lowercased())
  #expect(actual.inputs.keyMaterial == expected.inputs.keyMaterial)
  #expect(actual.inputs.preSharedKeys == expected.inputs.preSharedKeys)
  #expect(actual.inputs.payloads == expected.inputs.payloads)
  #expect(actual.expected.handshakeMessages == expected.expected.handshakeMessages)
  #expect(actual.expected.handshakeHash.lowercased() == expected.expected.handshakeHash.lowercased())
  #expect(actual.expected.splitTransportKeys == expected.expected.splitTransportKeys)
  #expect(actual.negativeCases.count == 2)
}

private func officialDocument(
  from fixture: NoiseVectorFixture,
  initiatorPskField: String,
  responderPskField: String
) -> String {
  let sortedMessages = fixture.expected.handshakeMessages.sorted { $0.index < $1.index }
  let sortedPayloads = fixture.inputs.payloads.sorted { $0.index < $1.index }
  let pskValues = fixture.inputs.preSharedKeys?
    .sorted { $0.key < $1.key }
    .map { $0.value.lowercased() } ?? []

  let messages = zip(sortedMessages, sortedPayloads).map { message, payload in
    let rawCiphertext = rawCiphertextHex(fromEncodedMessageHex: message.messageHex)
    return """
      {
        \"payload\": \"\(payload.plaintextHex.lowercased())\",
        \"ciphertext\": \"\(rawCiphertext)\"
      }
    """
  }.joined(separator: ",\n")

  let initiatorPsks = pskFieldJson(field: initiatorPskField, values: pskValues)
  let responderPsks = pskFieldJson(field: responderPskField, values: pskValues)
  let initiatorStatic = fixture.inputs.keyMaterial.initiator.static.private.lowercased()
  let initiatorEphemeral = fixture.inputs.keyMaterial.initiator.ephemeral.private.lowercased()
  let responderStatic = fixture.inputs.keyMaterial.responder.static.private.lowercased()
  let responderEphemeral = fixture.inputs.keyMaterial.responder.ephemeral.private.lowercased()

  return """
  {
    "vectors": [
    {
      "protocol_name": "\(fixture.protocolInfo.name)",
      "init_prologue": "\(fixture.inputs.prologue.lowercased())",
      "init_static": "\(initiatorStatic)",
      "init_ephemeral": "\(initiatorEphemeral)",
      "resp_prologue": "\(fixture.inputs.prologue.lowercased())",
      "resp_static": "\(responderStatic)",
      "resp_ephemeral": "\(responderEphemeral)",
      "handshake_hash": "\(fixture.expected.handshakeHash.lowercased())"\(initiatorPsks.isEmpty ? "" : ",\n          \(initiatorPsks)")\(responderPsks.isEmpty ? "" : ",\n          \(responderPsks)"),
      "messages": [
  \(messages)
      ]
    }
    ]
  }
  """
}

private func pskFieldJson(field: String, values: [String]) -> String {
  guard !values.isEmpty else { return "" }

  switch field {
  case "init_psk", "resp_psk":
    return "\"\(field)\": \"\(values[0])\""
  case "init_psks", "resp_psks":
    let joined = values.map { "\"\($0)\"" }.joined(separator: ", ")
    return "\"\(field)\": [\(joined)]"
  default:
    fatalError("Unsupported PSK field \(field)")
  }
}

private func rawCiphertextHex(fromEncodedMessageHex encodedMessageHex: String) -> String {
  let framed = try! NoiseHandshakeMessage(encoded: try! Data(noiseHex: encodedMessageHex))
  var raw = Data()
  framed.keyPayloads.forEach { raw.append($0) }
  raw.append(framed.payload)
  return raw.hexString
}

private func mutateHex(_ value: String) -> String {
  let replacement = value.hasPrefix("00") ? "ff" : "00"
  return replacement + value.dropFirst(2)
}

private func assertInvalidFixture(_ document: String, expectedMessage: String) async {
  do {
    _ = try await OfficialNoiseVectorConverter().convertDocument(document)
    Issue.record("Expected official vector conversion to fail with invalidFixture.")
  } catch let error as NoiseTestHarnessError {
    #expect(error == .invalidFixture(expectedMessage))
  } catch {
    Issue.record("Unexpected error type: \(error)")
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
      guard let value = UInt8(normalized[index..<nextIndex], radix: 16) else {
        throw NoiseTestHarnessError.invalidHex(rawHex)
      }
      data.append(value)
      index = nextIndex
    }
    self = data
  }

  var hexString: String {
    map { String(format: "%02x", $0) }.joined()
  }
}