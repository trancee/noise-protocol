package noise.protocol.testing

import noise.protocol.crypto.CryptoProvider
import noise.protocol.crypto.NoiseCryptoSuiteProvider
import java.nio.file.Path

data class OfficialNoiseVectorConversionRequest(
    val inputPath: Path,
    val outputDirectory: Path,
    val schemaPath: String
)

class OfficialNoiseVectorConverterCli(
    private val provider: NoiseCryptoSuiteProvider,
    private val converterFactory: (NoiseCryptoSuiteProvider) -> OfficialNoiseVectorConverter = ::OfficialNoiseVectorConverter
) {
    fun run(args: Array<String>): List<Path> {
        val request = parseArguments(args)
        return converterFactory(provider).convert(
            inputPath = request.inputPath,
            outputDirectory = request.outputDirectory,
            schemaPath = request.schemaPath
        )
    }

    fun parseArguments(args: Array<String>): OfficialNoiseVectorConversionRequest {
        var inputPath: String? = null
        var outputDirectory: String? = null
        var schemaPath: String = DEFAULT_SCHEMA_PATH

        var index = 0
        while (index < args.size) {
            when (args[index]) {
                "--input" -> inputPath = args.requireValue(++index, "--input")
                "--output-dir" -> outputDirectory = args.requireValue(++index, "--output-dir")
                "--schema-path" -> schemaPath = args.requireValue(++index, "--schema-path")
                else -> throw IllegalArgumentException(
                    "Unknown argument '${args[index]}'. Supported arguments: --input <path> --output-dir <path> [--schema-path <path>]."
                )
            }
            index += 1
        }

        val resolvedInput = inputPath ?: throw IllegalArgumentException(
            "Missing required argument --input <path>."
        )
        val resolvedOutput = outputDirectory ?: throw IllegalArgumentException(
            "Missing required argument --output-dir <path>."
        )

        return OfficialNoiseVectorConversionRequest(
            inputPath = Path.of(resolvedInput),
            outputDirectory = Path.of(resolvedOutput),
            schemaPath = schemaPath
        )
    }

    private fun Array<String>.requireValue(index: Int, flag: String): String {
        return getOrNull(index) ?: throw IllegalArgumentException(
            "Argument $flag requires a value."
        )
    }

    companion object {
        const val DEFAULT_SCHEMA_PATH: String = "../../schema/noise-vector-v1.schema.json"
    }
}

fun main(args: Array<String>) {
    val cli = OfficialNoiseVectorConverterCli(CryptoProvider())
    val writtenPaths = cli.run(args)
    println("Wrote ${writtenPaths.size} shared Noise fixture(s):")
    writtenPaths.forEach { println(it.toAbsolutePath().normalize()) }
}