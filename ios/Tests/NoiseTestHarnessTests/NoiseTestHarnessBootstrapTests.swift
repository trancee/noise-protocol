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
    let fixture = try loader.loadFixture(fileName: "noise-nn-placeholder.json")
    let runner = NoiseVectorRunner()

    let first = try await runner.verifyExpected(fixture)
    let second = try await runner.verifyExpected(fixture)

    #expect(first == second)
    #expect(first.handshakeMessages.count == fixture.inputs.payloads.count)
}

@Test("Negative-case hooks detect tamper and ordering failures")
func negativeCaseHooksDetectFailures() async throws {
    let loader = NoiseVectorFixtureLoader()
    let fixture = try loader.loadFixture(fileName: "noise-nn-placeholder.json")
    let runner = NoiseVectorRunner()

    for negativeCase in fixture.negativeCases {
        let result = try await runner.verifyNegativeCase(negativeCase, in: fixture)
        #expect(result.caseID == negativeCase.id)
        #expect(result.actualErrorCode == negativeCase.expectedError.code)
    }
}
