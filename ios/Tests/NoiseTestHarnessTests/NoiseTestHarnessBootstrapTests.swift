import Foundation
import Testing
@testable import NoiseTestHarness

private let expectedPatterns: Set<NoiseVectorPattern> = [.NN, .NK, .KK, .IK, .XX]
private let expectedDiffieHellman: Set<NoiseVectorDiffieHellman> = [.x25519, .x448]
private let expectedCiphers: Set<NoiseVectorCipher> = [.chaChaPoly, .aesGCM]
private let expectedHashes: Set<NoiseVectorHash> = [.sha256, .sha512, .blake2s, .blake2b]
private let representativePskVectorIDs: Set<String> = [
    "noise-nnpsk0-25519-chachapoly-sha256",
    "noise-xxpsk2-25519-chachapoly-sha256"
]

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

@Test("Deterministic execution matches expected artifacts for shared vector")
func deterministicExecutionMatchesExpectedArtifactsForSharedVector() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-nn-placeholder.json")
    let runner = NoiseVectorRunner()

    let result = try await runner.verifyExpected(fixture)

    #expect(result.handshakeMessages.count == fixture.expected.handshakeMessages.count)
    #expect(result.handshakeHashHex.lowercased() == fixture.expected.handshakeHash.lowercased())
    #expect(result.splitTransportKeys.initiator.txHex.lowercased() == fixture.expected.splitTransportKeys.initiator.tx.lowercased())
    #expect(result.splitTransportKeys.initiator.rxHex.lowercased() == fixture.expected.splitTransportKeys.initiator.rx.lowercased())
    #expect(result.splitTransportKeys.responder.txHex.lowercased() == fixture.expected.splitTransportKeys.responder.tx.lowercased())
    #expect(result.splitTransportKeys.responder.rxHex.lowercased() == fixture.expected.splitTransportKeys.responder.rx.lowercased())
}

@Test("Deterministic execution matches expected artifacts for representative PSK fixtures")
func deterministicExecutionMatchesExpectedArtifactsForRepresentativePskFixtures() async throws {
    let loader = NoiseVectorFixtureLoader()
    let runner = NoiseVectorRunner()

    for vectorID in representativePskVectorIDs.sorted() {
        let fixture = try loader.loadFixture(vectorID: vectorID)
        let result = try await runner.verifyExpected(fixture)

        #expect(result.handshakeMessages.count == fixture.expected.handshakeMessages.count)
        #expect(result.handshakeHashHex.lowercased() == fixture.expected.handshakeHash.lowercased())
    }
}

@Test("Deterministic execution matches expected artifacts for representative 448 fixture")
func deterministicExecutionMatchesExpectedArtifactsForRepresentative448Fixture() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-nn-448-chachapoly-sha256.json")
    let runner = NoiseVectorRunner()

    let result = try await runner.verifyExpected(fixture)

    #expect(result.handshakeMessages.count == fixture.expected.handshakeMessages.count)
    #expect(result.handshakeHashHex.lowercased() == fixture.expected.handshakeHash.lowercased())
}

@Test("Deterministic execution matches expected artifacts for representative BLAKE2 fixture")
func deterministicExecutionMatchesExpectedArtifactsForRepresentativeBlake2Fixture() async throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-nn-25519-chachapoly-blake2s.json")
    let runner = NoiseVectorRunner()

    let result = try await runner.verifyExpected(fixture)

    #expect(result.handshakeMessages.count == fixture.expected.handshakeMessages.count)
    #expect(result.handshakeHashHex.lowercased() == fixture.expected.handshakeHash.lowercased())
}

@Test("Fixture repository caches corpus and supports indexed lookup")
func fixtureRepositoryCachesCorpusAndSupportsIndexedLookup() async throws {
    let repository = NoiseVectorFixtureRepository()

    let firstCatalog = try await repository.catalog()
    let secondCatalog = try await repository.catalog()

    #expect(firstCatalog == secondCatalog)
    #expect(try await repository.fixtures().count == 82)
    #expect(try await repository.filter(pattern: .NN).count == 17)
    #expect(
        try await repository.filter(
            pattern: .NN,
            diffieHellman: .x448,
            cipher: .chaChaPoly,
            hash: .sha256
        ).count == 1
    )
    #expect(try await repository.fixture(vectorID: "noise-nn-placeholder").vectorID == "noise-nn-placeholder")
    #expect(
        try await repository.fixture(vectorID: "noise-nnpsk0-25519-chachapoly-sha256").vectorID
            == "noise-nnpsk0-25519-chachapoly-sha256"
    )
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

@Test("Runner resolves deterministic and negative checks from cached repository")
func runnerResolvesChecksFromCachedRepository() async throws {
    let repository = NoiseVectorFixtureRepository()
    let runner = NoiseVectorRunner()

    let deterministic = try await runner.verifyExpected(repository: repository, vectorID: "noise-nn-placeholder")
    #expect(deterministic.handshakeMessages.count == 2)

    let negative = try await runner.verifyNegativeCase(
        repository: repository,
        vectorID: "noise-nn-placeholder",
        caseID: "flip-tag-msg1"
    )
    #expect(negative.actualErrorCode == "decrypt_failed")
}

@Test("Runner reports supported shared fixtures for current iOS crypto registry")
func runnerReportsSupportedSharedFixtures() async throws {
    let repository = NoiseVectorFixtureRepository()
    let runner = NoiseVectorRunner()

    let supported = try await runner.supportedFixtures(repository: repository)

    #expect(supported.count == 82)
    for fixture in supported {
        #expect(await runner.supports(fixture))
    }
}

@Test("Fixture corpus covers full pattern and suite matrix")
func fixtureCorpusCoversFullPatternAndSuiteMatrix() throws {
    let fixtures = try NoiseVectorFixtureLoader().loadFixtures()
    let baseFixtures = fixtures.filter { ($0.inputs.preSharedKeys ?? [:]).isEmpty }
    let pskFixtures = fixtures.filter { !(($0.inputs.preSharedKeys ?? [:]).isEmpty) }

    #expect(fixtures.count == 82)
    #expect(baseFixtures.count == 80)
    #expect(Set(pskFixtures.map(\.vectorID)) == representativePskVectorIDs)

    struct CoverageKey: Hashable {
        let pattern: NoiseVectorPattern
        let dh: NoiseVectorDiffieHellman
        let cipher: NoiseVectorCipher
        let hash: NoiseVectorHash
    }

    let coverage = Dictionary(grouping: baseFixtures) { fixture in
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
    let repository = NoiseVectorFixtureRepository()
    let runner = NoiseVectorRunner()
    let fixtures = try await runner.supportedFixtures(repository: repository)
    #expect(fixtures.count == 82)

    for fixture in fixtures {
        _ = try await runner.verifyExpected(fixture)
    }
}

@Test("Fixture loader decodes representative PSK vector")
func fixtureLoaderDecodesRepresentativePskVector() throws {
    let fixture = try NoiseVectorFixtureLoader().loadFixture(fileName: "noise-nnpsk0-25519-chachapoly-sha256.json")

    #expect(fixture.protocolInfo.name == "Noise_NNpsk0_25519_ChaChaPoly_SHA256")
    #expect(fixture.inputs.preSharedKeys == [
        "psk0": "00112233445566778899aabbccddeefffedcba98765432100123456789abcdef"
    ])
}
