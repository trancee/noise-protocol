package noise.protocol.testing

import noise.protocol.crypto.CryptoProvider
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import kotlin.io.path.readText

class OfficialNoiseVectorConverterTest {
    private val converter = OfficialNoiseVectorConverter(CryptoProvider())
    private val harness = NoiseTestHarness(CryptoProvider())

    @Test
    fun convertsOfficialVectorDocumentIntoSharedFixtureFile() {
        val outputDirectory = Files.createTempDirectory("official-noise-converter-")

        val writtenPaths = converter.convertDocument(
            document = OfficialNoiseVectorImporterTest.OFFICIAL_NN_VECTOR_DOCUMENT,
            outputDirectory = outputDirectory
        )

        assertEquals(1, writtenPaths.size)
        val outputPath = writtenPaths.single()
        assertEquals("noise-nn-25519-chachapoly-sha256.json", outputPath.fileName.toString())

        val persisted = harness.loadFixture(outputPath)
        val runResult = harness.runDeterministic(persisted)

        assertEquals("noise-nn-25519-chachapoly-sha256", persisted.vectorId)
        assertEquals("Noise_NN_25519_ChaChaPoly_SHA256", persisted.protocol.name)
        assertEquals(true, runResult.passed)
        assertArrayEquals(persisted.expected.handshakeHash, runResult.handshakeHash)
        assertTrue(outputPath.readText().contains("\"${'$'}schema\": \"../../schema/noise-vector-v1.schema.json\""))
    }

    @Test
    fun writesConfiguredSchemaPathIntoPersistedFixture() {
        val outputDirectory = Files.createTempDirectory("official-noise-converter-schema-")

        val writtenPath = converter.convertDocument(
            document = OfficialNoiseVectorImporterTest.OFFICIAL_NN_VECTOR_DOCUMENT,
            outputDirectory = outputDirectory,
            schemaPath = "../schema/custom-noise-vector.schema.json"
        ).single()

        val persistedDocument = writtenPath.readText()
        assertTrue(persistedDocument.contains("\"${'$'}schema\": \"../schema/custom-noise-vector.schema.json\""))
    }
}