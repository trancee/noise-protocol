import CryptoKit
import Foundation
import Testing
@testable import NoiseTestHarness

@Test("Fixture loader decodes shared v1 vector")
func fixtureLoaderDecodesSharedVector() throws {
    let loader = NoiseVectorFixtureLoader()
    let fixture = try loader.loadFixture(fileName: "noise-nn-placeholder.json")

    #expect(fixture.schemaVersion == "1.0.0")
    #expect(fixture.vectorID == "noise-nn-placeholder")
    #expect(fixture.protocolInfo.pattern == .NN)
    #expect(fixture.inputs.payloads.count == 2)
    #expect(fixture.negativeCases.count == 2)
}

@Test("Deterministic execution is stable across runs")
func deterministicExecutionIsStableAcrossRuns() async throws {
    let loader = NoiseVectorFixtureLoader()
    let fixture = try executableFixture(
        from: loader.loadFixture(fileName: "noise-nn-placeholder.json")
    )
    let runner = NoiseVectorRunner()

    let first = try await runner.run(fixture)
    let second = try await runner.run(fixture)

    #expect(first == second)
    #expect(first.handshakeMessages.count == fixture.inputs.payloads.count)
}

@Test("Negative-case hooks detect tamper and ordering failures")
func negativeCaseHooksDetectFailures() async throws {
    let loader = NoiseVectorFixtureLoader()
    let fixture = try executableFixture(
        from: loader.loadFixture(fileName: "noise-nn-placeholder.json")
    )
    let runner = NoiseVectorRunner()

    for negativeCase in fixture.negativeCases {
        let result = try await runner.verifyNegativeCase(negativeCase, in: fixture)
        #expect(result.caseID == negativeCase.id)
        #expect(result.actualErrorCode == negativeCase.expectedError.code)
    }
}

private func executableFixture(from source: NoiseVectorFixture) throws -> NoiseVectorFixture {
    var fixture = source
    try assignKeyPair(&fixture.inputs.keyMaterial.initiator.static, seed: 0x10)
    try assignKeyPair(&fixture.inputs.keyMaterial.initiator.ephemeral, seed: 0x30)
    try assignKeyPair(&fixture.inputs.keyMaterial.responder.static, seed: 0x50)
    try assignKeyPair(&fixture.inputs.keyMaterial.responder.ephemeral, seed: 0x70)
    return fixture
}

private func assignKeyPair(_ keyPair: inout NoiseVectorKeyPair, seed: UInt8) throws {
    let privateKeyData = Data((0..<32).map { seed &+ UInt8($0) })
    let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
    keyPair.private = privateKeyData.hexString
    keyPair.public = privateKey.publicKey.rawRepresentation.hexString
}

private extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
