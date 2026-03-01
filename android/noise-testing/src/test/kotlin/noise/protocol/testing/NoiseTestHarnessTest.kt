package noise.protocol.testing

import noise.protocol.core.HandshakePattern
import noise.protocol.crypto.CryptoProvider
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path

class NoiseTestHarnessTest {
    private val harness = NoiseTestHarness(CryptoProvider())

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
        val fixture = harness.loadFixture(sharedFixturePath("noise-nn-placeholder.json"))

        val result = harness.runDeterministic(fixture)

        assertExpectedArtifacts(fixture, result)
    }

    @Test
    fun sharedFixtureCorpusCoversAllPatternAndSuiteCombinations() {
        val fixtures = harness.loadFixtures(sharedFixtureDirectory())

        assertEquals(80, fixtures.size)

        val expectedPatterns = HandshakePattern.entries.toSet()
        val expectedDhs = setOf(VectorDhAlgorithm.DH_25519, VectorDhAlgorithm.DH_448)
        val expectedCiphers = setOf(VectorCipherAlgorithm.CHACHA_POLY, VectorCipherAlgorithm.AES_GCM)
        val expectedHashes = setOf(
            VectorHashAlgorithm.SHA256,
            VectorHashAlgorithm.SHA512,
            VectorHashAlgorithm.BLAKE2S,
            VectorHashAlgorithm.BLAKE2B
        )

        val coverage = fixtures.groupBy {
            CoverageKey(
                pattern = it.protocol.pattern,
                dh = it.protocol.suite.dh,
                cipher = it.protocol.suite.cipher,
                hash = it.protocol.suite.hash
            )
        }

        assertTrue(coverage.values.all { it.size == 1 }, "Fixture corpus contains duplicate pattern/suite combinations.")

        expectedPatterns.forEach { pattern ->
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
        val fixtures = harness.loadFixtures(sharedFixtureDirectory())
        fixtures.forEach { fixture ->
            val result = harness.runDeterministic(fixture)
            assertExpectedArtifacts(fixture, result)
        }
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
        val fixture = harness.loadFixture(sharedFixturePath("noise-nn-placeholder.json"))

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
