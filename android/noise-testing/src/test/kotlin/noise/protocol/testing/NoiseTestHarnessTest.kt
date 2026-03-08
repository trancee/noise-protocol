package noise.protocol.testing

import noise.protocol.core.HandshakePattern
import noise.protocol.crypto.CryptoProvider
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class NoiseTestHarnessTest {
    private val harness = NoiseTestHarness(CryptoProvider())
    private val repository by lazy { harness.loadFixtureRepository(sharedFixtureDirectory()) }
    private val expectedSharedVectorPatterns = setOf(
        HandshakePattern.NN,
        HandshakePattern.NK,
        HandshakePattern.KK,
        HandshakePattern.IK,
        HandshakePattern.XX
    )
    private val representativePskVectorIds = setOf(
        "noise-nnpsk0-25519-chachapoly-sha256",
        "noise-xxpsk2-25519-chachapoly-sha256"
    )

    private data class CoverageKey(
        val pattern: HandshakePattern,
        val dh: VectorDhAlgorithm,
        val cipher: VectorCipherAlgorithm,
        val hash: VectorHashAlgorithm
    )

    @Test
    fun loadsSharedFixtureFromRepositoryVectors() {
        val fixturePath = sharedFixturePath("noise-nn-placeholder.json")

        val fixture = harness.loadFixture(fixturePath)

        assertEquals("1.0.0", fixture.schemaVersion)
        assertEquals("noise-nn-placeholder", fixture.vectorId)
        assertEquals(HandshakePattern.NN, fixture.protocol.pattern)
        assertEquals(2, fixture.inputs.payloads.size)
        assertEquals(2, fixture.expected.handshakeMessages.size)
        assertTrue(fixture.negativeCases.any { it.id == "flip-tag-msg1" })
        assertTrue(fixture.negativeCases.any { it.id == "reorder-handshake-messages" })
    }

    @Test
    fun deterministicRunMatchesFixtureExpectedArtifacts() {
        val fixture = repository.requireById("noise-nn-placeholder")

        val result = harness.runDeterministic(fixture)

        assertExpectedArtifacts(fixture, result)
    }

    @Test
    fun deterministicRunMatchesExpectedArtifactsForRepresentativePskFixtures() {
        representativePskVectorIds.forEach { vectorId ->
            val fixture = repository.requireById(vectorId)
            val result = harness.runDeterministic(fixture)
            assertExpectedArtifacts(fixture, result)
        }
    }

    @Test
    fun fixtureRepositoryCachesCorpusAndIndexesByVectorId() {
        val firstCatalog = repository.catalog()
        val secondCatalog = repository.catalog()

        assertSame(firstCatalog, secondCatalog)
        assertEquals(82, repository.all().size)
        assertEquals(17, repository.filter(pattern = HandshakePattern.NN).size)
        assertEquals(
            1,
            repository.filter(
                pattern = HandshakePattern.NN,
                dh = VectorDhAlgorithm.DH_448,
                cipher = VectorCipherAlgorithm.CHACHA_POLY,
                hash = VectorHashAlgorithm.SHA256
            ).size
        )
        assertEquals("noise-nn-placeholder", repository.requireById("noise-nn-placeholder").vectorId)
        assertEquals(
            "noise-nnpsk0-25519-chachapoly-sha256",
            repository.requireById("noise-nnpsk0-25519-chachapoly-sha256").vectorId
        )
    }

    @Test
    fun sharedFixtureCorpusCoversAllPatternAndSuiteCombinations() {
        val fixtures = repository.all()
        val baseFixtures = fixtures.filter { it.inputs.preSharedKeys.isEmpty() }
        val pskFixtures = fixtures.filter { it.inputs.preSharedKeys.isNotEmpty() }

        assertEquals(82, fixtures.size)
        assertEquals(80, baseFixtures.size)
        assertEquals(representativePskVectorIds, pskFixtures.map { it.vectorId }.toSet())

        val expectedDhs = setOf(VectorDhAlgorithm.DH_25519, VectorDhAlgorithm.DH_448)
        val expectedCiphers = setOf(VectorCipherAlgorithm.CHACHA_POLY, VectorCipherAlgorithm.AES_GCM)
        val expectedHashes = setOf(
            VectorHashAlgorithm.SHA256,
            VectorHashAlgorithm.SHA512,
            VectorHashAlgorithm.BLAKE2S,
            VectorHashAlgorithm.BLAKE2B
        )

        val coverage = baseFixtures.groupBy {
            CoverageKey(
                pattern = it.protocol.pattern,
                dh = it.protocol.suite.dh,
                cipher = it.protocol.suite.cipher,
                hash = it.protocol.suite.hash
            )
        }

        assertTrue(coverage.values.all { it.size == 1 }, "Fixture corpus contains duplicate pattern/suite combinations.")

        expectedSharedVectorPatterns.forEach { pattern ->
            expectedDhs.forEach { dh ->
                expectedCiphers.forEach { cipher ->
                    expectedHashes.forEach { hash ->
                        val key = CoverageKey(pattern = pattern, dh = dh, cipher = cipher, hash = hash)
                        assertTrue(
                            coverage.containsKey(key),
                            "Missing fixture for pattern=${pattern.name}, dh=${dh.name}, cipher=${cipher.name}, hash=${hash.name}"
                        )
                    }
                }
            }
        }
    }

    @Test
    fun deterministicRunMatchesExpectedArtifactsForAllSharedFixtures() {
        val fixtures = repository.all()
        fixtures.forEach { fixture ->
            val result = harness.runDeterministic(fixture)
            assertExpectedArtifacts(fixture, result)
        }
    }

    @Test
    fun deterministicAndNegativeRunsCanResolveFixturesFromRepository() {
        val deterministicResult = harness.runDeterministic(repository, "noise-nn-placeholder")
        assertTrue(deterministicResult.passed)

        val negativeResult = harness.runNegativeCase(repository, "noise-nn-placeholder", "flip-tag-msg1")
        assertFalse(negativeResult.passed)
        assertEquals("decrypt_failed", negativeResult.failure?.code)
    }

    @Test
    fun supportedFixturesReturnsEntireCorpusForAndroidProvider() {
        val supported = harness.supportedFixtures(repository)

        assertEquals(82, supported.size)
        assertTrue(supported.all(harness::isSupported))
    }

    @Test
    fun loadsRepresentativePskFixtureFromRepositoryVectors() {
        val fixturePath = sharedFixturePath("noise-nnpsk0-25519-chachapoly-sha256.json")

        val fixture = harness.loadFixture(fixturePath)

        assertEquals("Noise_NNpsk0_25519_ChaChaPoly_SHA256", fixture.protocol.name)
        assertArrayEquals(
            byteArrayOf(
                0x00, 0x11, 0x22, 0x33,
                0x44, 0x55, 0x66, 0x77,
                0x88.toByte(), 0x99.toByte(), 0xaa.toByte(), 0xbb.toByte(),
                0xcc.toByte(), 0xdd.toByte(), 0xee.toByte(), 0xff.toByte(),
                0xfe.toByte(), 0xdc.toByte(), 0xba.toByte(), 0x98.toByte(),
                0x76, 0x54, 0x32, 0x10,
                0x01, 0x23, 0x45, 0x67,
                0x89.toByte(), 0xab.toByte(), 0xcd.toByte(), 0xef.toByte()
            ),
            fixture.inputs.preSharedKeys.getValue(0)
        )
    }

    private fun assertExpectedArtifacts(fixture: NoiseVectorFixture, result: HarnessRunResult) {
        assertEquals(HarnessRunStatus.PASS, result.status)
        assertTrue(result.passed)
        assertNull(result.failure)

        val expectedMessages = fixture.expected.handshakeMessages.sortedBy { it.index }
        val actualMessages = result.transcript.sortedBy { it.index }
        assertEquals(expectedMessages.size, actualMessages.size)
        expectedMessages.zip(actualMessages).forEach { (expected, actual) ->
            assertEquals(expected.index, actual.index)
            assertEquals(expected.sender, actual.sender)
            assertArrayEquals(expected.message, actual.message)
        }

        val handshakeHash = result.handshakeHash
        assertNotNull(handshakeHash)
        assertArrayEquals(fixture.expected.handshakeHash, handshakeHash)

        val transportKeys = result.transportKeys
        assertNotNull(transportKeys)
        requireNotNull(transportKeys)
        assertArrayEquals(fixture.expected.splitTransportKeys.initiator.tx, transportKeys.initiatorTx)
        assertArrayEquals(fixture.expected.splitTransportKeys.initiator.rx, transportKeys.initiatorRx)
        assertArrayEquals(fixture.expected.splitTransportKeys.responder.tx, transportKeys.responderTx)
        assertArrayEquals(fixture.expected.splitTransportKeys.responder.rx, transportKeys.responderRx)
    }

    @Test
    fun negativeTagTamperAndReorderCasesFail() {
        val fixture = repository.requireById("noise-nn-placeholder")

        val tagTamperResult = harness.runNegativeCase(fixture, "flip-tag-msg1")
        assertFalse(tagTamperResult.passed)
        assertEquals("decrypt_failed", tagTamperResult.failure?.code)

        val reorderResult = harness.runNegativeCase(fixture, "reorder-handshake-messages")
        assertFalse(reorderResult.passed)
        assertEquals("unexpected_message_order", reorderResult.failure?.code)
    }

    private fun sharedFixturePath(fileName: String): Path {
        return sharedFixtureDirectory().resolve(fileName)
    }

    private fun sharedFixtureDirectory(): Path {
        val userDir = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        val candidates = listOf(
            userDir.resolve("../test-vectors/fixtures/v1").normalize(),
            userDir.resolve("../../test-vectors/fixtures/v1").normalize(),
            userDir.resolve("test-vectors/fixtures/v1").normalize()
        )

        return candidates.firstOrNull(Files::exists)
            ?: error("Unable to resolve shared vector fixture directory from $userDir")
    }
}
