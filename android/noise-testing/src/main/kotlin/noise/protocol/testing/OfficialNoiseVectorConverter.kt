package noise.protocol.testing

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import java.util.HexFormat
import kotlin.io.path.writeText

class NoiseVectorFixtureWriter(
    private val json: Json = Json { prettyPrint = true; prettyPrintIndent = "  " }
) {
    fun write(
        fixture: NoiseVectorFixture,
        outputPath: Path,
        schemaPath: String = DEFAULT_SCHEMA_PATH
    ): Path {
        outputPath.parent?.let(Files::createDirectories)
        outputPath.writeText(serialize(fixture, schemaPath))
        return outputPath
    }

    fun serialize(
        fixture: NoiseVectorFixture,
        schemaPath: String = DEFAULT_SCHEMA_PATH
    ): String {
        return json.encodeToString(JsonObject.serializer(), fixture.toJson(schemaPath)) + "\n"
    }

    private fun NoiseVectorFixture.toJson(schemaPath: String): JsonObject {
        return JsonObject(
            linkedMapOf<String, JsonElement>(
                "\$schema" to JsonPrimitive(schemaPath),
                "schema_version" to JsonPrimitive(schemaVersion),
                "vector_id" to JsonPrimitive(vectorId),
                "description" to (description?.let(::JsonPrimitive) ?: JsonNull),
                "protocol" to JsonObject(
                    linkedMapOf(
                        "name" to JsonPrimitive(protocol.name),
                        "pattern" to JsonPrimitive(protocol.pattern.name),
                        "suite" to JsonObject(
                            linkedMapOf(
                                "dh" to JsonPrimitive(protocol.suite.dh.toFixtureValue()),
                                "cipher" to JsonPrimitive(protocol.suite.cipher.toFixtureValue()),
                                "hash" to JsonPrimitive(protocol.suite.hash.toFixtureValue())
                            )
                        )
                    )
                ),
                "inputs" to JsonObject(
                    linkedMapOf(
                        "prologue" to JsonPrimitive(HEX.formatHex(inputs.prologue)),
                        "key_material" to JsonObject(
                            linkedMapOf(
                                "initiator" to inputs.keyMaterial.initiator.toJson(),
                                "responder" to inputs.keyMaterial.responder.toJson()
                            )
                        ),
                        "pre_shared_keys" to JsonObject(
                            inputs.preSharedKeys.toSortedMap().mapKeys { "psk${it.key}" }
                                .mapValues { JsonPrimitive(HEX.formatHex(it.value)) }
                        ),
                        "payloads" to JsonArray(inputs.payloads.sortedBy { it.index }.map { payload ->
                            JsonObject(
                                linkedMapOf(
                                    "index" to JsonPrimitive(payload.index),
                                    "sender" to JsonPrimitive(payload.sender.toFixtureValue()),
                                    "plaintext_hex" to JsonPrimitive(HEX.formatHex(payload.plaintext))
                                )
                            )
                        })
                    )
                ),
                "expected" to JsonObject(
                    linkedMapOf(
                        "handshake_messages" to JsonArray(expected.handshakeMessages.sortedBy { it.index }.map { message ->
                            JsonObject(
                                linkedMapOf(
                                    "index" to JsonPrimitive(message.index),
                                    "sender" to JsonPrimitive(message.sender.toFixtureValue()),
                                    "message_hex" to JsonPrimitive(HEX.formatHex(message.message))
                                )
                            )
                        }),
                        "handshake_hash" to JsonPrimitive(HEX.formatHex(expected.handshakeHash)),
                        "split_transport_keys" to JsonObject(
                            linkedMapOf(
                                "initiator" to expected.splitTransportKeys.initiator.toJson(),
                                "responder" to expected.splitTransportKeys.responder.toJson()
                            )
                        )
                    )
                ),
                "negative_cases" to JsonArray(negativeCases.map { negativeCase ->
                    JsonObject(
                        linkedMapOf<String, kotlinx.serialization.json.JsonElement>(
                            "id" to JsonPrimitive(negativeCase.id),
                            "description" to JsonPrimitive(negativeCase.description),
                            "phase" to JsonPrimitive(negativeCase.phase.toFixtureValue())
                        ).apply {
                            negativeCase.messageIndex?.let { put("message_index", JsonPrimitive(it)) }
                            put(
                                "mutation",
                                JsonObject(
                                    linkedMapOf(
                                        "target" to JsonPrimitive(negativeCase.mutation.target.toFixtureValue()),
                                        "operation" to JsonPrimitive(negativeCase.mutation.operation)
                                    )
                                )
                            )
                            put(
                                "expected_error",
                                JsonObject(
                                    linkedMapOf(
                                        "code" to JsonPrimitive(negativeCase.expectedError.code),
                                        "detail" to (negativeCase.expectedError.detail?.let(::JsonPrimitive) ?: JsonNull)
                                    )
                                )
                            )
                        }
                    )
                })
            )
        )
    }

    private fun VectorPartyKeyMaterial.toJson(): JsonObject {
        return JsonObject(
            linkedMapOf(
                "static" to staticKey.toJson(),
                "ephemeral" to ephemeralKey.toJson()
            )
        )
    }

    private fun VectorKeyPair.toJson(): JsonObject {
        return JsonObject(
            linkedMapOf(
                "private" to JsonPrimitive(HEX.formatHex(privateKey)),
                "public" to JsonPrimitive(HEX.formatHex(publicKey))
            )
        )
    }

    private fun VectorTransportKeys.toJson(): JsonObject {
        return JsonObject(
            linkedMapOf(
                "tx" to JsonPrimitive(HEX.formatHex(tx)),
                "rx" to JsonPrimitive(HEX.formatHex(rx))
            )
        )
    }

    private fun VectorDhAlgorithm.toFixtureValue(): String = when (this) {
        VectorDhAlgorithm.DH_25519 -> "25519"
        VectorDhAlgorithm.DH_448 -> "448"
    }

    private fun VectorCipherAlgorithm.toFixtureValue(): String = when (this) {
        VectorCipherAlgorithm.CHACHA_POLY -> "ChaChaPoly"
        VectorCipherAlgorithm.AES_GCM -> "AESGCM"
    }

    private fun VectorHashAlgorithm.toFixtureValue(): String = when (this) {
        VectorHashAlgorithm.SHA256 -> "SHA256"
        VectorHashAlgorithm.SHA512 -> "SHA512"
        VectorHashAlgorithm.BLAKE2S -> "BLAKE2s"
        VectorHashAlgorithm.BLAKE2B -> "BLAKE2b"
    }

    private fun VectorSender.toFixtureValue(): String = when (this) {
        VectorSender.INITIATOR -> "initiator"
        VectorSender.RESPONDER -> "responder"
    }

    private fun VectorPhase.toFixtureValue(): String = when (this) {
        VectorPhase.HANDSHAKE -> "handshake"
        VectorPhase.TRANSPORT -> "transport"
    }

    private fun VectorMutationTarget.toFixtureValue(): String = when (this) {
        VectorMutationTarget.CIPHERTEXT -> "ciphertext"
        VectorMutationTarget.TAG -> "tag"
        VectorMutationTarget.PAYLOAD -> "payload"
        VectorMutationTarget.NONCE -> "nonce"
        VectorMutationTarget.PUBLIC_KEY -> "public_key"
        VectorMutationTarget.MESSAGE_ORDER -> "message_order"
    }

    private companion object {
        val HEX: HexFormat = HexFormat.of()
        const val DEFAULT_SCHEMA_PATH: String = "../../schema/noise-vector-v1.schema.json"
    }
}

class OfficialNoiseVectorConverter(
    provider: noise.protocol.crypto.NoiseCryptoSuiteProvider,
    private val importer: OfficialNoiseVectorImporter = OfficialNoiseVectorImporter(provider),
    private val writer: NoiseVectorFixtureWriter = NoiseVectorFixtureWriter()
) {
    fun convertDocument(
        document: String,
        outputDirectory: Path,
        schemaPath: String = DEFAULT_SCHEMA_PATH
    ): List<Path> {
        val fixtures = importer.importDocument(document)
        Files.createDirectories(outputDirectory)
        return fixtures.map { fixture ->
            writer.write(
                fixture = fixture,
                outputPath = outputDirectory.resolve("${fixture.vectorId}.json"),
                schemaPath = schemaPath
            )
        }
    }

    fun convert(
        inputPath: Path,
        outputDirectory: Path,
        schemaPath: String = DEFAULT_SCHEMA_PATH
    ): List<Path> {
        return convertDocument(inputPath.toFile().readText(), outputDirectory, schemaPath)
    }

    private companion object {
        const val DEFAULT_SCHEMA_PATH: String = "../../schema/noise-vector-v1.schema.json"
    }
}