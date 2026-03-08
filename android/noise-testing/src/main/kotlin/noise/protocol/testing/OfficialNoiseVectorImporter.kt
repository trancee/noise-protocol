package noise.protocol.testing

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import noise.protocol.core.HandshakeMessage
import noise.protocol.core.HandshakePattern
import noise.protocol.core.HandshakeToken
import noise.protocol.crypto.NoiseCryptoSuiteProvider
import noise.protocol.crypto.NoiseDhAdapter
import java.nio.file.Path
import java.util.HexFormat
import kotlin.io.path.readText

class OfficialNoiseVectorImporter(
    private val provider: NoiseCryptoSuiteProvider,
    private val json: Json = Json { ignoreUnknownKeys = false }
) {
    fun importDocument(document: String): List<NoiseVectorFixture> {
        val root = json.parseToJsonElement(document).jsonObject
        val vectors = root.requireArray("vectors")
        val assignedIds = LinkedHashMap<String, Int>()

        return vectors.mapIndexed { index, element ->
            val vector = element.jsonObject
            val baseId = defaultVectorId(vector, index)
            val occurrence = assignedIds.merge(baseId, 1, Int::plus) ?: 1
            val vectorId = if (occurrence == 1) baseId else "$baseId-$occurrence"
            importVector(vector, vectorId)
        }
    }

    fun import(path: Path): List<NoiseVectorFixture> = importDocument(path.readText())

    fun importVector(document: String, index: Int, vectorId: String? = null): NoiseVectorFixture {
        val root = json.parseToJsonElement(document).jsonObject
        val vectors = root.requireArray("vectors")
        require(index in 0 until vectors.size) {
            "Official Noise vector index $index is out of bounds for document with ${vectors.size} vectors."
        }

        val vector = vectors[index].jsonObject
        return importVector(vector, vectorId ?: defaultVectorId(vector, index))
    }

    private fun importVector(vector: JsonObject, vectorId: String): NoiseVectorFixture {
        require(vector.optionalBoolean("fail") != true) {
            "Official Noise vectors marked fail=true cannot be translated into passing shared fixtures."
        }
        require(vector.optionalBoolean("fallback") != true) {
            "Official Noise fallback vectors are not representable by the shared v1 fixture contract."
        }
        require(vector.optionalString("hybrid") == null) {
            "Official Noise hybrid vectors are not representable by the shared v1 fixture contract."
        }

        val protocolName = vector.requireString("protocol_name")
        val descriptor = parseProtocolDescriptor(protocolName)
        val initPrologue = vector.requireHex("init_prologue")
        val respPrologue = vector.requireHex("resp_prologue")
        require(initPrologue.contentEquals(respPrologue)) {
            "Official Noise vectors with asymmetric initiator/responder prologues are not representable by the shared v1 fixture contract."
        }

        val suite = provider.createSuite(descriptor.suite.toNoiseAlgorithms())
        val diffieHellman = suite.diffieHellman as? NoiseDhAdapter
            ?: error("Configured suite diffie-hellman adapter does not support public-key derivation.")

        val initiatorStatic = resolveKeyPair(
            privateKey = vector.optionalHex("init_static"),
            fallbackSeed = 0x11,
            diffieHellman = diffieHellman,
            keyLabel = "init_static"
        )
        val initiatorEphemeral = resolveKeyPair(
            privateKey = vector.optionalHex("init_ephemeral"),
            fallbackSeed = 0x21,
            diffieHellman = diffieHellman,
            keyLabel = "init_ephemeral"
        )
        val responderStatic = resolveKeyPair(
            privateKey = vector.optionalHex("resp_static"),
            fallbackSeed = 0x31,
            diffieHellman = diffieHellman,
            keyLabel = "resp_static"
        )
        val responderEphemeral = resolveKeyPair(
            privateKey = vector.optionalHex("resp_ephemeral"),
            fallbackSeed = 0x41,
            diffieHellman = diffieHellman,
            keyLabel = "resp_ephemeral"
        )

        vector.optionalHex("init_remote_static")?.let { expectedResponderPublic ->
            require(expectedResponderPublic.contentEquals(responderStatic.publicKey)) {
                "Official init_remote_static does not match the responder static public key derived for $protocolName."
            }
        }
        vector.optionalHex("resp_remote_static")?.let { expectedInitiatorPublic ->
            require(expectedInitiatorPublic.contentEquals(initiatorStatic.publicKey)) {
                "Official resp_remote_static does not match the initiator static public key derived for $protocolName."
            }
        }

        val pskPlacements = descriptor.pskPlacements.sorted()
        val initiatorPsks = vector.optionalHexArray("init_psks") ?: vector.optionalHexArray("init_psk") ?: emptyList()
        val responderPsks = vector.optionalHexArray("resp_psks") ?: vector.optionalHexArray("resp_psk") ?: emptyList()
        require(initiatorPsks.size == responderPsks.size) {
            "Official Noise PSK arrays must match for both parties to translate into the shared v1 fixture contract."
        }
        require(initiatorPsks.indices.all { initiatorPsks[it].contentEquals(responderPsks[it]) }) {
            "Official Noise PSK arrays differ between initiator and responder; shared v1 fixtures store a single agreed PSK set."
        }
        require(initiatorPsks.size == pskPlacements.size) {
            "Official Noise vector PSK count ${initiatorPsks.size} does not match protocol placements ${pskPlacements.size} for $protocolName."
        }
        val preSharedKeys = pskPlacements.mapIndexed { index, placement -> placement to initiatorPsks[index] }.toMap()

        val officialMessages = vector.requireArray("messages")
        val handshakeMessageCount = descriptor.pattern.messages.size
        require(officialMessages.size >= handshakeMessageCount) {
            "Official Noise vector provides ${officialMessages.size} messages, but $protocolName requires $handshakeMessageCount handshake messages."
        }

        val payloads = officialMessages.take(handshakeMessageCount).mapIndexed { index, element ->
            val message = element.jsonObject
            VectorPayload(
                index = index,
                sender = descriptor.pattern.messages[index].direction.toSender(),
                plaintext = message.requireHex("payload")
            )
        }

        val pendingFixture = NoiseVectorFixture(
            schemaVersion = "1.0.0",
            vectorId = vectorId,
            description = buildDescription(vector),
            protocol = VectorProtocol(
                name = protocolName,
                pattern = descriptor.pattern,
                suite = descriptor.suite
            ),
            inputs = VectorInputs(
                prologue = initPrologue,
                keyMaterial = VectorKeyMaterial(
                    initiator = VectorPartyKeyMaterial(
                        staticKey = VectorKeyPair(initiatorStatic.privateKey, initiatorStatic.publicKey),
                        ephemeralKey = VectorKeyPair(initiatorEphemeral.privateKey, initiatorEphemeral.publicKey)
                    ),
                    responder = VectorPartyKeyMaterial(
                        staticKey = VectorKeyPair(responderStatic.privateKey, responderStatic.publicKey),
                        ephemeralKey = VectorKeyPair(responderEphemeral.privateKey, responderEphemeral.publicKey)
                    )
                ),
                preSharedKeys = preSharedKeys,
                payloads = payloads
            ),
            expected = VectorExpected(
                handshakeMessages = emptyList(),
                handshakeHash = ByteArray(0),
                splitTransportKeys = VectorSplitTransportKeys(
                    initiator = VectorTransportKeys(ByteArray(0), ByteArray(0)),
                    responder = VectorTransportKeys(ByteArray(0), ByteArray(0))
                )
            ),
            negativeCases = emptyList()
        )

        val runResult = NoiseTestHarness(provider).runDeterministic(pendingFixture)
        require(runResult.passed) {
            "Translated official Noise vector $protocolName did not execute successfully: ${runResult.failure?.detail ?: "unknown failure"}."
        }

        val computedHandshakeMessages = runResult.transcript.mapIndexed { index, transcriptMessage ->
            val expectedTokens = descriptor.pattern.messages[index].tokens.filter { token ->
                token == HandshakeToken.E || token == HandshakeToken.S
            }
            val decoded = HandshakeMessage.decode(
                direction = descriptor.pattern.messages[index].direction,
                expectedTokens = expectedTokens,
                encoded = transcriptMessage.message
            )
            val computedRaw = decoded.rawMessageBytes()
            val expectedRaw = officialMessages[index].jsonObject.requireHex("ciphertext")
            require(computedRaw.contentEquals(expectedRaw)) {
                "Translated official Noise vector handshake message $index for $protocolName does not match the official ciphertext."
            }

            VectorExpectedHandshakeMessage(
                index = index,
                sender = transcriptMessage.sender,
                message = transcriptMessage.message
            )
        }

        val computedHandshakeHash = runResult.handshakeHash
            ?: error("Translated official Noise vector did not produce a handshake hash.")
        vector.optionalHex("handshake_hash")?.let { expectedHandshakeHash ->
            require(computedHandshakeHash.contentEquals(expectedHandshakeHash)) {
                "Translated official Noise vector handshake hash for $protocolName does not match the official handshake_hash."
            }
        }

        val transportKeys = requireNotNull(runResult.transportKeys) {
            "Translated official Noise vector did not produce split transport keys."
        }

        return pendingFixture.copy(
            expected = VectorExpected(
                handshakeMessages = computedHandshakeMessages,
                handshakeHash = computedHandshakeHash,
                splitTransportKeys = VectorSplitTransportKeys(
                    initiator = VectorTransportKeys(
                        tx = requireNotNull(transportKeys.initiatorTx),
                        rx = requireNotNull(transportKeys.initiatorRx)
                    ),
                    responder = VectorTransportKeys(
                        tx = requireNotNull(transportKeys.responderTx),
                        rx = requireNotNull(transportKeys.responderRx)
                    )
                )
            ),
            negativeCases = defaultNegativeCases(handshakeMessageCount)
        )
    }

    private fun buildDescription(vector: JsonObject): String {
        val name = vector.optionalString("name")
        val protocolName = vector.requireString("protocol_name")
        return if (name != null && name != protocolName) {
            "Imported from official Noise wiki vector '$name'."
        } else {
            "Imported from the official Noise wiki vector for $protocolName."
        }
    }

    private fun defaultNegativeCases(handshakeMessageCount: Int): List<VectorNegativeCase> {
        val cases = mutableListOf(
            VectorNegativeCase(
                id = "flip-tag-final-message",
                description = "Flip one bit in the final authentication tag on the last handshake message.",
                phase = VectorPhase.HANDSHAKE,
                messageIndex = handshakeMessageCount - 1,
                mutation = VectorMutation(
                    target = VectorMutationTarget.TAG,
                    operation = "flip_last_bit"
                ),
                expectedError = VectorExpectedError(
                    code = "decrypt_failed",
                    detail = "Handshake must abort and clear transient state."
                )
            )
        )

        if (handshakeMessageCount > 1) {
            cases += VectorNegativeCase(
                id = "reorder-handshake-messages",
                description = "Deliver message index 1 before message index 0.",
                phase = VectorPhase.HANDSHAKE,
                messageIndex = null,
                mutation = VectorMutation(
                    target = VectorMutationTarget.MESSAGE_ORDER,
                    operation = "swap_0_1"
                ),
                expectedError = VectorExpectedError(
                    code = "unexpected_message_order",
                    detail = "Implementation must reject out-of-order handshake traffic."
                )
            )
        }

        return cases
    }

    private fun resolveKeyPair(
        privateKey: ByteArray?,
        fallbackSeed: Int,
        diffieHellman: NoiseDhAdapter,
        keyLabel: String
    ): noise.protocol.core.NoiseKeyPair {
        val resolvedPrivateKey = privateKey ?: ByteArray(diffieHellman.privateKeyLength) { index ->
            (fallbackSeed + index).toByte()
        }
        return try {
            diffieHellman.deriveKeyPair(resolvedPrivateKey)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException(
                "Official Noise vector field $keyLabel has invalid length for the selected DH algorithm.",
                error
            )
        }
    }

    private fun parseProtocolDescriptor(protocolName: String): ParsedProtocolDescriptor {
        val parts = protocolName.split('_')
        require(parts.size == 5 && parts.first() == "Noise") {
            "Official Noise protocol name '$protocolName' is not in the expected Noise_<pattern>_<dh>_<cipher>_<hash> format."
        }

        val patternSegment = parts[1]
        val match = PROTOCOL_PATTERN.matchEntire(patternSegment)
            ?: throw IllegalArgumentException(
                "Official Noise protocol name '$protocolName' uses unsupported pattern modifiers."
            )

        val basePattern = match.groupValues[1]
        val modifierSegment = match.groupValues[2]
        val handshakePattern = HandshakePattern.entries.firstOrNull { it.name == basePattern }
            ?: throw IllegalArgumentException(
                "Official Noise protocol name '$protocolName' uses unsupported handshake pattern '$basePattern'."
            )
        val pskPlacements = PSK_PATTERN.findAll(modifierSegment).map { it.groupValues[1].toInt() }.toSet()
        require(pskPlacements.size == PSK_PATTERN.findAll(modifierSegment).count()) {
            "Official Noise protocol name '$protocolName' contains duplicate pskN modifiers."
        }
        require(pskPlacements.all { it in 0..handshakePattern.messages.size }) {
            "Official Noise protocol name '$protocolName' contains unsupported pskN placements."
        }

        val suite = VectorSuite(
            dh = when (parts[2]) {
                "25519" -> VectorDhAlgorithm.DH_25519
                "448" -> VectorDhAlgorithm.DH_448
                else -> throw IllegalArgumentException("Unsupported official Noise DH algorithm '${parts[2]}'.")
            },
            cipher = when (parts[3]) {
                "ChaChaPoly" -> VectorCipherAlgorithm.CHACHA_POLY
                "AESGCM" -> VectorCipherAlgorithm.AES_GCM
                else -> throw IllegalArgumentException("Unsupported official Noise cipher '${parts[3]}'.")
            },
            hash = when (parts[4]) {
                "SHA256" -> VectorHashAlgorithm.SHA256
                "SHA512" -> VectorHashAlgorithm.SHA512
                "BLAKE2s" -> VectorHashAlgorithm.BLAKE2S
                "BLAKE2b" -> VectorHashAlgorithm.BLAKE2B
                else -> throw IllegalArgumentException("Unsupported official Noise hash '${parts[4]}'.")
            }
        )

        return ParsedProtocolDescriptor(
            pattern = handshakePattern,
            suite = suite,
            pskPlacements = pskPlacements
        )
    }

    private fun defaultVectorId(vector: JsonObject, index: Int): String {
        val base = normalizeId(vector.requireString("protocol_name"))
        val name = vector.optionalString("name")
            ?.takeIf { it != vector.requireString("protocol_name") }
            ?.let(::normalizeId)
        val candidate = if (name.isNullOrBlank()) base else "$base-$name"
        return if (candidate.isBlank()) "official-noise-vector-${index + 1}" else candidate
    }

    private fun normalizeId(value: String): String {
        return value.lowercase()
            .replace(Regex("[^a-z0-9]+"), "-")
            .trim('-')
    }

    private fun HandshakeMessage.rawMessageBytes(): ByteArray {
        val size = tokenValues.sumOf { it.data.size } + payload.size
        val raw = ByteArray(size)
        var offset = 0
        tokenValues.forEach { tokenValue ->
            tokenValue.data.copyInto(raw, destinationOffset = offset)
            offset += tokenValue.data.size
        }
        payload.copyInto(raw, destinationOffset = offset)
        return raw
    }

    private fun JsonObject.requireArray(fieldName: String): JsonArray {
        return this[fieldName]?.jsonArray ?: error("Official Noise vector field '$fieldName' is missing or is not an array.")
    }

    private fun JsonObject.requireString(fieldName: String): String {
        return (this[fieldName] as? JsonPrimitive)?.contentOrNull
            ?: error("Official Noise vector field '$fieldName' is missing or is not a string.")
    }

    private fun JsonObject.optionalString(fieldName: String): String? {
        return (this[fieldName] as? JsonPrimitive)?.contentOrNull
    }

    private fun JsonObject.optionalBoolean(fieldName: String): Boolean? {
        return (this[fieldName] as? JsonPrimitive)?.booleanOrNull
    }

    private fun JsonObject.requireHex(fieldName: String): ByteArray {
        return decodeHex(requireString(fieldName), fieldName)
    }

    private fun JsonObject.optionalHex(fieldName: String): ByteArray? {
        val value = optionalString(fieldName) ?: return null
        return decodeHex(value, fieldName)
    }

    private fun JsonObject.optionalHexArray(fieldName: String): List<ByteArray>? {
        val value = this[fieldName] ?: return null
        return when (value) {
            is JsonArray -> value.mapIndexed { index, element ->
                decodeHex(element.jsonPrimitive.content, "$fieldName[$index]")
            }
            is JsonPrimitive -> listOf(decodeHex(value.content, fieldName))
            else -> error("Official Noise vector field '$fieldName' is not a string or array.")
        }
    }

    private fun decodeHex(value: String, fieldName: String): ByteArray {
        return try {
            HEX.parseHex(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Official Noise vector field '$fieldName' is not valid hex.", error)
        }
    }

    private fun noise.protocol.core.MessageDirection.toSender(): VectorSender {
        return when (this) {
            noise.protocol.core.MessageDirection.INITIATOR_TO_RESPONDER -> VectorSender.INITIATOR
            noise.protocol.core.MessageDirection.RESPONDER_TO_INITIATOR -> VectorSender.RESPONDER
        }
    }

    private data class ParsedProtocolDescriptor(
        val pattern: HandshakePattern,
        val suite: VectorSuite,
        val pskPlacements: Set<Int>
    )

    private companion object {
        val HEX: HexFormat = HexFormat.of()
        val PROTOCOL_PATTERN = Regex("^([A-Z]+)((?:psk\\d+)?(?:\\+psk\\d+)*)$")
        val PSK_PATTERN = Regex("psk(\\d+)")
    }
}