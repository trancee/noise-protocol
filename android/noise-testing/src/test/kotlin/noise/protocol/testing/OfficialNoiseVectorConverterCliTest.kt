package noise.protocol.testing

import noise.protocol.crypto.CryptoProvider
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files
import kotlin.io.path.writeText

class OfficialNoiseVectorConverterCliTest {
    private val cli = OfficialNoiseVectorConverterCli(CryptoProvider())

    @Test
    fun parsesRequiredArgumentsAndDefaultSchemaPath() {
        val request = cli.parseArguments(
            arrayOf("--input", "/tmp/official.json", "--output-dir", "/tmp/out")
        )

        assertEquals("/tmp/official.json", request.inputPath.toString())
        assertEquals("/tmp/out", request.outputDirectory.toString())
        assertEquals(OfficialNoiseVectorConverterCli.DEFAULT_SCHEMA_PATH, request.schemaPath)
    }

    @Test
    fun rejectsUnknownArguments() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            cli.parseArguments(arrayOf("--wat"))
        }

        assertEquals(
            "Unknown argument '--wat'. Supported arguments: --input <path> --output-dir <path> [--schema-path <path>].",
            error.message
        )
    }

    @Test
    fun convertsInputDocumentFromCliArguments() {
        val inputPath = Files.createTempFile("official-noise-cli-", ".json")
        val outputDirectory = Files.createTempDirectory("official-noise-cli-out-")
        inputPath.writeText(OfficialNoiseVectorImporterTest.OFFICIAL_NN_VECTOR_DOCUMENT)

        val writtenPaths = cli.run(
            arrayOf(
                "--input", inputPath.toString(),
                "--output-dir", outputDirectory.toString(),
                "--schema-path", "../schema/noise-vector-v1.schema.json"
            )
        )

        assertEquals(1, writtenPaths.size)
        assertEquals("noise-nn-25519-chachapoly-sha256.json", writtenPaths.single().fileName.toString())
        assertTrue(Files.exists(writtenPaths.single()))
    }
}