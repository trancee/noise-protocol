package noise.protocol.testing

import noise.protocol.core.HandshakeMessage
import noise.protocol.core.HandshakePattern
import noise.protocol.core.HandshakeRole
import noise.protocol.core.HandshakeState
import noise.protocol.core.MessageDirection
import noise.protocol.core.NoiseCryptoSuite
import noise.protocol.core.NoiseKeyPair
import noise.protocol.crypto.NoiseAeadAlgorithm
import noise.protocol.crypto.NoiseCryptoAlgorithms
import noise.protocol.crypto.NoiseCryptoSuiteProvider
import noise.protocol.crypto.NoiseDhAlgorithm
import noise.protocol.crypto.NoiseHashAlgorithm
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import java.util.HexFormat
import kotlin.io.path.readText
import kotlin.streams.asSequence

data class NoiseVectorFixture(
    val schemaVersion: String,
    val vectorId: String,
    val description: String?,
    val protocol: VectorProtocol,
    val inputs: VectorInputs,
    val expected: VectorExpected,
    val negativeCases: List<VectorNegativeCase>
)

data class VectorProtocol(
    val name: String,
    val pattern: HandshakePattern,
    val suite: VectorSuite
)

data class VectorSuite(
    val dh: VectorDhAlgorithm,
    val cipher: VectorCipherAlgorithm,
    val hash: VectorHashAlgorithm
) {
    fun toNoiseAlgorithms(): NoiseCryptoAlgorithms {
        return NoiseCryptoAlgorithms(
            dh = when (dh) {
                VectorDhAlgorithm.DH_25519 -> NoiseDhAlgorithm.X25519
                VectorDhAlgorithm.DH_448 -> NoiseDhAlgorithm.X448
            },
            aead = when (cipher) {
                VectorCipherAlgorithm.CHACHA_POLY -> NoiseAeadAlgorithm.CHACHA20_POLY1305
                VectorCipherAlgorithm.AES_GCM -> NoiseAeadAlgorithm.AES_GCM
            },
            hash = when (hash) {
                VectorHashAlgorithm.SHA256 -> NoiseHashAlgorithm.SHA256
                VectorHashAlgorithm.SHA512 -> NoiseHashAlgorithm.SHA512
                VectorHashAlgorithm.BLAKE2S -> NoiseHashAlgorithm.BLAKE2S
                VectorHashAlgorithm.BLAKE2B -> NoiseHashAlgorithm.BLAKE2B
            }
        )
    }
}

enum class VectorDhAlgorithm {
    DH_25519,
    DH_448
}

enum class VectorCipherAlgorithm {
    CHACHA_POLY,
    AES_GCM
}

enum class VectorHashAlgorithm {
    SHA256,
    SHA512,
    BLAKE2S,
    BLAKE2B
}

data class VectorInputs(
    val prologue: ByteArray,
    val keyMaterial: VectorKeyMaterial,
    val payloads: List<VectorPayload>
)

data class VectorKeyMaterial(
    val initiator: VectorPartyKeyMaterial,
    val responder: VectorPartyKeyMaterial
)

data class VectorPartyKeyMaterial(
    val staticKey: VectorKeyPair,
    val ephemeralKey: VectorKeyPair
)

data class VectorKeyPair(
    val privateKey: ByteArray,
    val publicKey: ByteArray
) {
    fun toNoiseKeyPair(): NoiseKeyPair = NoiseKeyPair(
        privateKey = privateKey.copyOf(),
        publicKey = publicKey.copyOf()
    )
}

data class VectorPayload(
    val index: Int,
    val sender: VectorSender,
    val plaintext: ByteArray
)

data class VectorExpected(
    val handshakeMessages: List<VectorExpectedHandshakeMessage>,
    val handshakeHash: ByteArray,
    val splitTransportKeys: VectorSplitTransportKeys
)

data class VectorExpectedHandshakeMessage(
    val index: Int,
    val sender: VectorSender,
    val message: ByteArray
)

data class VectorSplitTransportKeys(
    val initiator: VectorTransportKeys,
    val responder: VectorTransportKeys
)

data class VectorTransportKeys(
    val tx: ByteArray,
    val rx: ByteArray
)

enum class VectorSender {
    INITIATOR,
    RESPONDER
}

data class VectorNegativeCase(
    val id: String,
    val description: String,
    val phase: VectorPhase,
    val messageIndex: Int?,
    val mutation: VectorMutation,
    val expectedError: VectorExpectedError
)

enum class VectorPhase {
    HANDSHAKE,
    TRANSPORT
}

data class VectorMutation(
    val target: VectorMutationTarget,
    val operation: String
)

enum class VectorMutationTarget {
    CIPHERTEXT,
    TAG,
    PAYLOAD,
    NONCE,
    PUBLIC_KEY,
    MESSAGE_ORDER
}

data class VectorExpectedError(
    val code: String,
    val detail: String?
)

data class HarnessMessageContext(
    val index: Int,
    val sender: VectorSender,
    val message: HandshakeMessage
)

data class HarnessRunHooks(
    val mutateMessage: (HarnessMessageContext) -> HandshakeMessage = { context -> context.message },
    val shouldDeliverMessage: (HarnessMessageContext) -> Boolean = { true }
)

enum class HarnessRunStatus {
    PASS,
    FAIL
}

data class HarnessFailure(
    val code: String,
    val detail: String,
    val messageIndex: Int? = null
)

data class HarnessTranscriptMessage(
    val index: Int,
    val sender: VectorSender,
    val message: ByteArray
)

data class HarnessTransportKeys(
    val initiatorTx: ByteArray?,
    val initiatorRx: ByteArray?,
    val responderTx: ByteArray?,
    val responderRx: ByteArray?
)

data class HarnessRunResult(
    val status: HarnessRunStatus,
    val transcript: List<HarnessTranscriptMessage>,
    val handshakeHash: ByteArray? = null,
    val transportKeys: HarnessTransportKeys? = null,
    val failure: HarnessFailure? = null
) {
    val passed: Boolean
        get() = status == HarnessRunStatus.PASS
}

class NoiseVectorFixtureLoader(
    private val json: Json = Json { ignoreUnknownKeys = false }
) {
    fun load(path: Path): NoiseVectorFixture {
        val root = json.parseToJsonElement(path.readText()).jsonObject
        return parseFixture(root)
    }

    fun loadAll(fixturesDirectory: Path): List<NoiseVectorFixture> {
        return Files.list(fixturesDirectory).use { stream ->
            stream.asSequence()
                .filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".json") }
                .sortedBy { it.fileName.toString() }
                .map(::load)
                .toList()
        }
    }

    private fun parseFixture(root: JsonObject): NoiseVectorFixture {
        val protocol = parseProtocol(root.requireObject("protocol"))
        return NoiseVectorFixture(
            schemaVersion = root.requireString("schema_version"),
            vectorId = root.requireString("vector_id"),
            description = root.optionalString("description"),
            protocol = protocol,
            inputs = parseInputs(root.requireObject("inputs")),
            expected = parseExpected(root.requireObject("expected")),
            negativeCases = root.requireArray("negative_cases").map { parseNegativeCase(it.jsonObject) }
        )
    }

    private fun parseProtocol(protocolObject: JsonObject): VectorProtocol {
        return VectorProtocol(
            name = protocolObject.requireString("name"),
            pattern = protocolObject.requireHandshakePattern("pattern"),
            suite = parseSuite(protocolObject.requireObject("suite"))
        )
    }

    private fun parseSuite(suiteObject: JsonObject): VectorSuite {
        return VectorSuite(
            dh = when (suiteObject.requireString("dh")) {
                "25519" -> VectorDhAlgorithm.DH_25519
                "448" -> VectorDhAlgorithm.DH_448
                else -> error("Unsupported DH value in fixture suite.")
            },
            cipher = when (suiteObject.requireString("cipher")) {
                "ChaChaPoly" -> VectorCipherAlgorithm.CHACHA_POLY
                "AESGCM" -> VectorCipherAlgorithm.AES_GCM
                else -> error("Unsupported cipher value in fixture suite.")
            },
            hash = when (suiteObject.requireString("hash")) {
                "SHA256" -> VectorHashAlgorithm.SHA256
                "SHA512" -> VectorHashAlgorithm.SHA512
                "BLAKE2s" -> VectorHashAlgorithm.BLAKE2S
                "BLAKE2b" -> VectorHashAlgorithm.BLAKE2B
                else -> error("Unsupported hash value in fixture suite.")
            }
        )
    }

    private fun parseInputs(inputsObject: JsonObject): VectorInputs {
        return VectorInputs(
            prologue = inputsObject.requireHex("prologue"),
            keyMaterial = parseKeyMaterial(inputsObject.requireObject("key_material")),
            payloads = inputsObject.requireArray("payloads").map { parsePayload(it.jsonObject) }
        )
    }

    private fun parseKeyMaterial(keyMaterialObject: JsonObject): VectorKeyMaterial {
        return VectorKeyMaterial(
            initiator = parsePartyKeyMaterial(keyMaterialObject.requireObject("initiator")),
            responder = parsePartyKeyMaterial(keyMaterialObject.requireObject("responder"))
        )
    }

    private fun parsePartyKeyMaterial(partyObject: JsonObject): VectorPartyKeyMaterial {
        return VectorPartyKeyMaterial(
            staticKey = parseKeyPair(partyObject.requireObject("static")),
            ephemeralKey = parseKeyPair(partyObject.requireObject("ephemeral"))
        )
    }

    private fun parseKeyPair(keyPairObject: JsonObject): VectorKeyPair {
        return VectorKeyPair(
            privateKey = keyPairObject.requireHex("private"),
            publicKey = keyPairObject.requireHex("public")
        )
    }

    private fun parsePayload(payloadObject: JsonObject): VectorPayload {
        return VectorPayload(
            index = payloadObject.requireInt("index"),
            sender = payloadObject.requireSender("sender"),
            plaintext = payloadObject.requireHex("plaintext_hex")
        )
    }

    private fun parseExpected(expectedObject: JsonObject): VectorExpected {
        return VectorExpected(
            handshakeMessages = expectedObject.requireArray("handshake_messages")
                .map { parseExpectedHandshakeMessage(it.jsonObject) },
            handshakeHash = expectedObject.requireHex("handshake_hash"),
            splitTransportKeys = parseSplitTransportKeys(expectedObject.requireObject("split_transport_keys"))
        )
    }

    private fun parseExpectedHandshakeMessage(messageObject: JsonObject): VectorExpectedHandshakeMessage {
        return VectorExpectedHandshakeMessage(
            index = messageObject.requireInt("index"),
            sender = messageObject.requireSender("sender"),
            message = messageObject.requireHex("message_hex")
        )
    }

    private fun parseSplitTransportKeys(keysObject: JsonObject): VectorSplitTransportKeys {
        return VectorSplitTransportKeys(
            initiator = parseTransportKeys(keysObject.requireObject("initiator")),
            responder = parseTransportKeys(keysObject.requireObject("responder"))
        )
    }

    private fun parseTransportKeys(transportObject: JsonObject): VectorTransportKeys {
        return VectorTransportKeys(
            tx = transportObject.requireHex("tx"),
            rx = transportObject.requireHex("rx")
        )
    }

    private fun parseNegativeCase(negativeCaseObject: JsonObject): VectorNegativeCase {
        return VectorNegativeCase(
            id = negativeCaseObject.requireString("id"),
            description = negativeCaseObject.requireString("description"),
            phase = negativeCaseObject.requirePhase("phase"),
            messageIndex = negativeCaseObject.optionalInt("message_index"),
            mutation = parseMutation(negativeCaseObject.requireObject("mutation")),
            expectedError = parseExpectedError(negativeCaseObject.requireObject("expected_error"))
        )
    }

    private fun parseMutation(mutationObject: JsonObject): VectorMutation {
        return VectorMutation(
            target = mutationObject.requireMutationTarget("target"),
            operation = mutationObject.requireString("operation")
        )
    }

    private fun parseExpectedError(errorObject: JsonObject): VectorExpectedError {
        return VectorExpectedError(
            code = errorObject.requireString("code"),
            detail = errorObject.optionalString("detail")
        )
    }

    private fun JsonObject.requireObject(fieldName: String): JsonObject {
        return this[fieldName]?.jsonObject ?: error("Fixture field '$fieldName' is missing or is not an object.")
    }

    private fun JsonObject.requireArray(fieldName: String): JsonArray {
        return this[fieldName]?.jsonArray ?: error("Fixture field '$fieldName' is missing or is not an array.")
    }

    private fun JsonObject.requireString(fieldName: String): String {
        return this[fieldName]?.jsonPrimitive?.contentOrNull
            ?: error("Fixture field '$fieldName' is missing or is not a string.")
    }

    private fun JsonObject.optionalString(fieldName: String): String? {
        return this[fieldName]?.jsonPrimitive?.contentOrNull
    }

    private fun JsonObject.requireInt(fieldName: String): Int {
        return this[fieldName]?.jsonPrimitive?.intOrNull
            ?: error("Fixture field '$fieldName' is missing or is not an integer.")
    }

    private fun JsonObject.optionalInt(fieldName: String): Int? {
        return this[fieldName]?.jsonPrimitive?.intOrNull
    }

    private fun JsonObject.requireHex(fieldName: String): ByteArray {
        val value = requireString(fieldName)
        return try {
            HEX_FORMAT.parseHex(value)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Fixture field '$fieldName' is not valid hexadecimal.", error)
        }
    }

    private fun JsonObject.requireHandshakePattern(fieldName: String): HandshakePattern {
        val value = requireString(fieldName)
        return runCatching { HandshakePattern.valueOf(value) }
            .getOrElse { error("Unsupported handshake pattern '$value'.") }
    }

    private fun JsonObject.requireSender(fieldName: String): VectorSender {
        return when (requireString(fieldName)) {
            "initiator" -> VectorSender.INITIATOR
            "responder" -> VectorSender.RESPONDER
            else -> error("Unsupported sender value in fixture field '$fieldName'.")
        }
    }

    private fun JsonObject.requirePhase(fieldName: String): VectorPhase {
        return when (requireString(fieldName)) {
            "handshake" -> VectorPhase.HANDSHAKE
            "transport" -> VectorPhase.TRANSPORT
            else -> error("Unsupported phase value in fixture field '$fieldName'.")
        }
    }

    private fun JsonObject.requireMutationTarget(fieldName: String): VectorMutationTarget {
        return when (requireString(fieldName)) {
            "ciphertext" -> VectorMutationTarget.CIPHERTEXT
            "tag" -> VectorMutationTarget.TAG
            "payload" -> VectorMutationTarget.PAYLOAD
            "nonce" -> VectorMutationTarget.NONCE
            "public_key" -> VectorMutationTarget.PUBLIC_KEY
            "message_order" -> VectorMutationTarget.MESSAGE_ORDER
            else -> error("Unsupported mutation target value in fixture field '$fieldName'.")
        }
    }

    private companion object {
        val HEX_FORMAT: HexFormat = HexFormat.of()
    }
}

class NoiseTestHarness(
    private val provider: NoiseCryptoSuiteProvider,
    private val fixtureLoader: NoiseVectorFixtureLoader = NoiseVectorFixtureLoader()
) {
    fun loadFixture(path: Path): NoiseVectorFixture = fixtureLoader.load(path)

    fun loadFixtures(fixturesDirectory: Path): List<NoiseVectorFixture> = fixtureLoader.loadAll(fixturesDirectory)

    fun runDeterministic(
        vector: NoiseVectorFixture,
        hooks: HarnessRunHooks = HarnessRunHooks()
    ): HarnessRunResult {
        if (!provider.supports(vector.protocol.pattern)) {
            return failed(
                code = "unsupported_pattern",
                detail = "Provider '${provider.id}' does not support pattern ${vector.protocol.pattern.name}."
            )
        }

        val suite = runCatching { provider.createSuite(vector.protocol.suite.toNoiseAlgorithms()) }
            .getOrElse {
                return failed(
                    code = "unsupported_suite",
                    detail = it.message ?: "Provider '${provider.id}' failed to create suite."
                )
            }

        val states = initializeStates(vector, suite)
        val payloadByIndex = vector.inputs.payloads.associateBy { it.index }
        val transcript = mutableListOf<HarnessTranscriptMessage>()

        for ((index, messagePattern) in vector.protocol.pattern.messages.withIndex()) {
            val sender = messagePattern.direction.toSender()
            val senderState = states.stateFor(sender)
            val receiverState = states.stateFor(sender.opposite())

            val payloadEntry = payloadByIndex[index]
            if (payloadEntry != null && payloadEntry.sender != sender) {
                return failed(
                    code = "payload_sender_mismatch",
                    detail = "Payload sender for message $index does not match handshake direction.",
                    messageIndex = index,
                    transcript = transcript
                )
            }

            val payload = payloadEntry?.plaintext ?: EMPTY
            val outbound = runCatching { senderState.writeMessage(payload) }
                .getOrElse {
                    return failedFromThrowable(it, index, transcript)
                }

            val context = HarnessMessageContext(index = index, sender = sender, message = outbound)
            val mutatedMessage = runCatching { hooks.mutateMessage(context) }
                .getOrElse {
                    return failed(
                        code = "mutation_failed",
                        detail = it.message ?: "Mutation failed for message $index.",
                        messageIndex = index,
                        transcript = transcript
                    )
                }

            transcript += HarnessTranscriptMessage(
                index = index,
                sender = sender,
                message = encodeMessage(mutatedMessage)
            )

            if (!hooks.shouldDeliverMessage(context.copy(message = mutatedMessage))) {
                continue
            }

            val decryptedPayload = runCatching { receiverState.readMessage(mutatedMessage) }
                .getOrElse {
                    return failedFromThrowable(it, index, transcript)
                }

            if (!decryptedPayload.contentEquals(payload)) {
                return failed(
                    code = "payload_mismatch",
                    detail = "Decrypted payload mismatch for message $index.",
                    messageIndex = index,
                    transcript = transcript
                )
            }
        }

        if (!states.initiator.isComplete() || !states.responder.isComplete()) {
            return failed(
                code = "handshake_incomplete",
                detail = "Handshake transcript did not complete on both peers.",
                transcript = transcript
            )
        }

        val initiatorHandshakeHash = states.initiator.handshakeHash()
        val responderHandshakeHash = states.responder.handshakeHash()
        if (!initiatorHandshakeHash.contentEquals(responderHandshakeHash)) {
            return failed(
                code = "handshake_hash_mismatch",
                detail = "Initiator and responder handshake hashes diverged.",
                transcript = transcript
            )
        }

        val initiatorTransport = runCatching { states.initiator.splitTransportStates() }
            .getOrElse { return failedFromThrowable(it, null, transcript) }
        val responderTransport = runCatching { states.responder.splitTransportStates() }
            .getOrElse { return failedFromThrowable(it, null, transcript) }

        return HarnessRunResult(
            status = HarnessRunStatus.PASS,
            transcript = transcript,
            handshakeHash = initiatorHandshakeHash,
            transportKeys = HarnessTransportKeys(
                initiatorTx = initiatorTransport.first.keyMaterial(),
                initiatorRx = initiatorTransport.second.keyMaterial(),
                responderTx = responderTransport.first.keyMaterial(),
                responderRx = responderTransport.second.keyMaterial()
            )
        )
    }

    fun runNegativeCase(vector: NoiseVectorFixture, caseId: String): HarnessRunResult {
        val negativeCase = vector.negativeCases.firstOrNull { it.id == caseId }
            ?: return failed(
                code = "missing_negative_case",
                detail = "Negative case '$caseId' does not exist in fixture '${vector.vectorId}'."
            )
        return runNegativeCase(vector, negativeCase)
    }

    fun runNegativeCase(vector: NoiseVectorFixture, negativeCase: VectorNegativeCase): HarnessRunResult {
        val hooks = runCatching { hooksForNegativeCase(negativeCase) }
            .getOrElse {
                return failed(
                    code = "unsupported_mutation",
                    detail = it.message ?: "Negative case '${negativeCase.id}' is unsupported."
                )
            }

        val result = runDeterministic(vector, hooks)
        return if (result.passed) {
            failed(
                code = "negative_case_not_triggered",
                detail = "Negative case '${negativeCase.id}' did not fail as expected.",
                transcript = result.transcript
            )
        } else {
            result
        }
    }

    private fun initializeStates(vector: NoiseVectorFixture, suite: NoiseCryptoSuite): PartyStates {
        val initiatorStatic = vector.inputs.keyMaterial.initiator.staticKey.toNoiseKeyPair()
        val responderStatic = vector.inputs.keyMaterial.responder.staticKey.toNoiseKeyPair()
        val initiatorEphemeralQueue = DeterministicEphemeralQueue(listOf(vector.inputs.keyMaterial.initiator.ephemeralKey))
        val responderEphemeralQueue = DeterministicEphemeralQueue(listOf(vector.inputs.keyMaterial.responder.ephemeralKey))

        val initiatorState = HandshakeState.initialize(
            pattern = vector.protocol.pattern,
            role = HandshakeRole.INITIATOR,
            cryptoSuite = suite,
            protocolName = vector.protocol.name,
            prologue = vector.inputs.prologue,
            localStatic = initiatorStatic,
            remoteStatic = responderStatic.publicKey,
            ephemeralKeyGenerator = initiatorEphemeralQueue::next
        )
        val responderState = HandshakeState.initialize(
            pattern = vector.protocol.pattern,
            role = HandshakeRole.RESPONDER,
            cryptoSuite = suite,
            protocolName = vector.protocol.name,
            prologue = vector.inputs.prologue,
            localStatic = responderStatic,
            remoteStatic = initiatorStatic.publicKey,
            ephemeralKeyGenerator = responderEphemeralQueue::next
        )

        return PartyStates(initiator = initiatorState, responder = responderState)
    }

    private fun hooksForNegativeCase(negativeCase: VectorNegativeCase): HarnessRunHooks {
        require(negativeCase.phase == VectorPhase.HANDSHAKE) {
            "Only handshake-phase negative cases are currently supported."
        }

        return when (negativeCase.mutation.target) {
            VectorMutationTarget.TAG -> {
                require(negativeCase.mutation.operation == "flip_last_bit") {
                    "Unsupported tag mutation operation '${negativeCase.mutation.operation}'."
                }
                val index = requireNotNull(negativeCase.messageIndex) {
                    "Tag mutation requires message_index in fixture negative case '${negativeCase.id}'."
                }
                HarnessRunHooks(
                    mutateMessage = { context ->
                        if (context.index != index) {
                            context.message
                        } else {
                            context.message.copy(payload = context.message.payload.flipLastBit())
                        }
                    }
                )
            }

            VectorMutationTarget.MESSAGE_ORDER -> {
                require(negativeCase.mutation.operation == "swap_0_1") {
                    "Unsupported message order mutation operation '${negativeCase.mutation.operation}'."
                }
                HarnessRunHooks(
                    shouldDeliverMessage = { context -> context.index != 0 }
                )
            }

            else -> throw UnsupportedOperationException(
                "Mutation target '${negativeCase.mutation.target}' is not implemented yet."
            )
        }
    }

    private fun failedFromThrowable(
        error: Throwable,
        messageIndex: Int?,
        transcript: List<HarnessTranscriptMessage>
    ): HarnessRunResult {
        val detail = error.message ?: error::class.simpleName ?: "Unknown handshake error."
        return failed(
            code = classifyFailure(error),
            detail = detail,
            messageIndex = messageIndex,
            transcript = transcript
        )
    }

    private fun classifyFailure(error: Throwable): String {
        val detail = error.message.orEmpty()
        return when {
            detail.contains("Authentication failed", ignoreCase = true) -> "decrypt_failed"
            detail.contains("Expected to read before writing", ignoreCase = true) ||
                detail.contains("Expected to write before reading", ignoreCase = true) ||
                detail.contains("Unexpected message direction", ignoreCase = true) ||
                detail.contains("Unexpected token order", ignoreCase = true) -> "unexpected_message_order"

            else -> "handshake_failed"
        }
    }

    private fun failed(
        code: String,
        detail: String,
        messageIndex: Int? = null,
        transcript: List<HarnessTranscriptMessage> = emptyList()
    ): HarnessRunResult {
        return HarnessRunResult(
            status = HarnessRunStatus.FAIL,
            transcript = transcript.toList(),
            failure = HarnessFailure(
                code = code,
                detail = detail,
                messageIndex = messageIndex
            )
        )
    }

    private fun encodeMessage(message: HandshakeMessage): ByteArray {
        require(message.tokenValues.size <= UShort.MAX_VALUE.toInt()) {
            "Handshake message contains too many token payload segments."
        }
        require(message.payload.size <= UShort.MAX_VALUE.toInt()) {
            "Handshake message payload exceeds UInt16 maximum."
        }

        val size = 2 + message.tokenValues.sumOf { 2 + it.data.size } + 2 + message.payload.size
        val encoded = ByteArray(size)
        var offset = 0
        fun writeUInt16(value: Int) {
            encoded[offset] = ((value ushr 8) and 0xFF).toByte()
            encoded[offset + 1] = (value and 0xFF).toByte()
            offset += 2
        }

        writeUInt16(message.tokenValues.size)
        message.tokenValues.forEach { tokenValue ->
            require(tokenValue.data.size <= UShort.MAX_VALUE.toInt()) {
                "Handshake token payload exceeds UInt16 maximum."
            }
            writeUInt16(tokenValue.data.size)
            tokenValue.data.copyInto(encoded, destinationOffset = offset)
            offset += tokenValue.data.size
        }
        writeUInt16(message.payload.size)
        message.payload.copyInto(encoded, destinationOffset = offset)

        return encoded
    }

    private fun MessageDirection.toSender(): VectorSender {
        return when (this) {
            MessageDirection.INITIATOR_TO_RESPONDER -> VectorSender.INITIATOR
            MessageDirection.RESPONDER_TO_INITIATOR -> VectorSender.RESPONDER
        }
    }

    private fun VectorSender.opposite(): VectorSender {
        return when (this) {
            VectorSender.INITIATOR -> VectorSender.RESPONDER
            VectorSender.RESPONDER -> VectorSender.INITIATOR
        }
    }

    private data class PartyStates(
        val initiator: HandshakeState,
        val responder: HandshakeState
    ) {
        fun stateFor(sender: VectorSender): HandshakeState {
            return when (sender) {
                VectorSender.INITIATOR -> initiator
                VectorSender.RESPONDER -> responder
            }
        }
    }

    private class DeterministicEphemeralQueue(keys: List<VectorKeyPair>) {
        private val queue: ArrayDeque<VectorKeyPair> = ArrayDeque(keys)

        fun next(): NoiseKeyPair {
            val nextKey = queue.removeFirstOrNull()
                ?: error("No deterministic ephemeral keys remain in the fixture.")
            return nextKey.toNoiseKeyPair()
        }
    }

    private fun ByteArray.flipLastBit(): ByteArray {
        require(isNotEmpty()) { "Cannot mutate an empty payload." }
        val mutated = copyOf()
        mutated[mutated.lastIndex] = (mutated[mutated.lastIndex].toInt() xor 0x01).toByte()
        return mutated
    }

    private companion object {
        val EMPTY = ByteArray(0)
    }
}
