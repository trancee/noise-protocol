import Foundation
import Testing
@testable import NoiseTestHarness

private let expectedPatterns: Set<NoiseVectorPattern> = [.NN, .NK, .KK, .IK, .XX]
private let expectedDiffieHellman: Set<NoiseVectorDiffieHellman> = [.x25519, .x448]
private let expectedCiphers: Set<NoiseVectorCipher> = [.chaChaPoly, .aesGCM]
private let expectedHashes: Set<NoiseVectorHash> = [.sha256, .sha512, .blake2s, .blake2b]

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

@Test("Fixture corpus covers full pattern and suite matrix")
func fixtureCorpusCoversFullPatternAndSuiteMatrix() throws {
    let fixtures = try NoiseVectorFixtureLoader().loadFixtures()
    #expect(fixtures.count == 80)

    struct CoverageKey: Hashable {
        let pattern: NoiseVectorPattern
        let dh: NoiseVectorDiffieHellman
        let cipher: NoiseVectorCipher
        let hash: NoiseVectorHash
    }

    let coverage = Dictionary(grouping: fixtures) { fixture in
        CoverageKey(
            pattern: fixture.protocolInfo.pattern,
            dh: fixture.protocolInfo.suite.dh,
            cipher: fixture.protocolInfo.suite.cipher,
            hash: fixture.protocolInfo.suite.hash
        )
    }
    #expect(coverage.values.allSatisfy { $0.count == 1 })

    for pattern in expectedPatterns {
        for dh in expectedDiffieHellman {
            for cipher in expectedCiphers {
                for hash in expectedHashes {
                    let key = CoverageKey(pattern: pattern, dh: dh, cipher: cipher, hash: hash)
                    #expect(coverage[key] != nil)
                }
            }
        }
    }
}

@Test("Deterministic execution validates all iOS-supported fixtures")
func deterministicExecutionValidatesAllSupportedFixtures() async throws {
    let fixtures = try NoiseVectorFixtureLoader().loadFixtures()
        .filter {
            $0.protocolInfo.suite.dh == .x25519 &&
                ($0.protocolInfo.suite.hash == .sha256 || $0.protocolInfo.suite.hash == .sha512)
        }
    #expect(fixtures.count == 20)

    let runner = NoiseVectorRunner()
    for fixture in fixtures {
        _ = try await runner.verifyExpected(fixture)
    }
}
