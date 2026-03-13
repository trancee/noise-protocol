package com.noise.protocol

import com.noise.protocol.crypto.*
import com.noise.protocol.pattern.HandshakePattern
import com.noise.protocol.state.HandshakeState
import com.noise.protocol.state.TransportState
import org.json.JSONObject
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import java.util.stream.Stream

/** Sequential key pair generator serving keys in order. */
class SequentialKeyPairGenerator(private val keys: List<ByteArray>) : NoiseKeyPairGenerator {
    private var index = 0
    override fun generate(): NoiseKeyPair {
        require(index < keys.size) { "No more keys" }
        return NoiseKeyPair.fromPrivateKey(keys[index++])
    }
}

/** Hex conversion helpers. */
fun String.hexToBytes(): ByteArray {
    val clean = replace(" ", "").replace("\n", "")
    return ByteArray(clean.length / 2) { i ->
        clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
}

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

data class TestMessage(val payload: ByteArray, val ciphertext: ByteArray)

class TestVectorTests {

    companion object {
        private val SUITE_FILES = listOf(
            "noise_25519_ChaChaPoly_SHA256",
            "noise_25519_ChaChaPoly_SHA512",
            "noise_25519_ChaChaPoly_BLAKE2s",
            "noise_25519_ChaChaPoly_BLAKE2b",
            "noise_25519_AESGCM_SHA256",
            "noise_25519_AESGCM_SHA512",
            "noise_25519_AESGCM_BLAKE2s",
            "noise_25519_AESGCM_BLAKE2b",
        )

        private val SUITE_MAP = mapOf(
            "noise_25519_ChaChaPoly_SHA256" to CipherSuite.NOISE_25519_CHACHAPOLY_SHA256,
            "noise_25519_ChaChaPoly_SHA512" to CipherSuite.NOISE_25519_CHACHAPOLY_SHA512,
            "noise_25519_ChaChaPoly_BLAKE2s" to CipherSuite.NOISE_25519_CHACHAPOLY_BLAKE2S,
            "noise_25519_ChaChaPoly_BLAKE2b" to CipherSuite.NOISE_25519_CHACHAPOLY_BLAKE2B,
            "noise_25519_AESGCM_SHA256" to CipherSuite.NOISE_25519_AESGCM_SHA256,
            "noise_25519_AESGCM_SHA512" to CipherSuite.NOISE_25519_AESGCM_SHA512,
            "noise_25519_AESGCM_BLAKE2s" to CipherSuite.NOISE_25519_AESGCM_BLAKE2S,
            "noise_25519_AESGCM_BLAKE2b" to CipherSuite.NOISE_25519_AESGCM_BLAKE2B,
        )

        private val suiteData: Map<String, JSONObject> = SUITE_FILES.associateWith { name ->
            val stream = TestVectorTests::class.java.getResourceAsStream("/$name.json")
                ?: error("Test vector JSON not found: $name.json")
            JSONObject(stream.bufferedReader().readText())
        }

        // Default suite data for the XXfallback test
        private val defaultJson = suiteData["noise_25519_ChaChaPoly_SHA256"]!!
        private val defaultKeys = defaultJson.getJSONObject("keys")

        fun resolveKey(keys: JSONObject, keyName: String): ByteArray =
            keys.getString(keyName).hexToBytes()

        fun resolveOptionalKey(keys: JSONObject, vector: JSONObject, field: String): ByteArray? {
            if (vector.isNull(field)) return null
            return resolveKey(keys, vector.getString(field))
        }

        fun parseMessages(array: org.json.JSONArray): List<TestMessage> =
            (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                TestMessage(
                    payload = obj.getString("payload").hexToBytes(),
                    ciphertext = obj.getString("ciphertext").hexToBytes()
                )
            }

        fun resolvePsks(keys: JSONObject, vector: JSONObject): List<ByteArray> {
            val arr = vector.getJSONArray("psks")
            return (0 until arr.length()).map { resolveKey(keys, arr.getString(it)) }
        }

        /** Provides test arguments for all suite x pattern combinations. */
        @JvmStatic
        fun allVectorTests(): Stream<Arguments> {
            val args = mutableListOf<Arguments>()
            for ((suiteName, json) in suiteData) {
                val suite = SUITE_MAP[suiteName]!!
                val vectors = json.getJSONArray("vectors")
                for (i in 0 until vectors.length()) {
                    val vector = vectors.getJSONObject(i)
                    val pattern = vector.getString("pattern")
                    val displayName = "${suite.cipherName}_${suite.hashName}/$pattern"
                    args.add(Arguments.of(displayName, suiteName, pattern))
                }
            }
            return args.stream()
        }
    }

    // MARK: - Parameterized test for all suite x pattern combinations

    @ParameterizedTest(name = "{0}")
    @MethodSource("allVectorTests")
    fun testVector(displayName: String, suiteName: String, patternName: String) {
        val json = suiteData[suiteName]!!
        val suite = SUITE_MAP[suiteName]!!
        val keys = json.getJSONObject("keys")
        val vectors = json.getJSONArray("vectors")

        var vector: JSONObject? = null
        for (i in 0 until vectors.length()) {
            val v = vectors.getJSONObject(i)
            if (v.getString("pattern") == patternName) { vector = v; break }
        }
        assertNotNull(vector, "Vector not found: $suiteName/$patternName")

        val initiatorStatic = resolveOptionalKey(keys, vector, "init_static")
        val responderStatic = resolveOptionalKey(keys, vector, "resp_static")
        val initiatorRemoteStatic = resolveOptionalKey(keys, vector, "init_remote_static")
        val responderRemoteStatic = resolveOptionalKey(keys, vector, "resp_remote_static")
        val psks = resolvePsks(keys, vector)
        val handshakeMessages = parseMessages(vector.getJSONArray("handshake_messages"))
        val transportMessages = parseMessages(vector.getJSONArray("transport_messages"))
        val expectedHash = vector.getString("handshake_hash").hexToBytes()

        runHandshakeTest(
            suite = suite,
            pattern = HandshakePattern.named(patternName),
            initiatorStatic = initiatorStatic,
            responderStatic = responderStatic,
            initiatorRemoteStatic = initiatorRemoteStatic,
            responderRemoteStatic = responderRemoteStatic,
            psks = psks,
            handshakeMessages = handshakeMessages,
            transportMessages = transportMessages,
            expectedHandshakeHash = expectedHash,
            keys = keys
        )
    }

    // MARK: - XXfallback (only in ChaChaPoly_SHA256)

    @Test
    fun testXXfallback() {
        val keys = defaultKeys
        val fallbackVectors = defaultJson.getJSONArray("fallback_vectors")
        var vector: JSONObject? = null
        for (i in 0 until fallbackVectors.length()) {
            val v = fallbackVectors.getJSONObject(i)
            if (v.getString("pattern") == "XXfallback") { vector = v; break }
        }
        assertNotNull(vector, "XXfallback vector not found")

        val initEphemeral = resolveKey(keys, "init_ephemeral")
        val respEphemeral = resolveKey(keys, "resp_ephemeral")
        val initStatic = resolveKey(keys, "init_static")
        val respStatic = resolveKey(keys, "resp_static")
        val initEphPub = resolveKey(keys, "init_eph_pub")

        val wrongRemoteStatic = vector.getString("wrong_remote_static").hexToBytes()
        val fallbackPrologue = vector.getString("fallback_prologue").hexToBytes()

        val ikMsg1Vector = vector.getJSONObject("ik_message1")
        val ikMsg1Payload = ikMsg1Vector.getString("payload").hexToBytes()
        val ikMsg1Expected = ikMsg1Vector.getString("ciphertext").hexToBytes()

        val fallbackMessages = parseMessages(vector.getJSONArray("fallback_messages"))
        val expectedHash = vector.getString("handshake_hash").hexToBytes()

        val transportObj = vector.getJSONObject("transport_message")
        val transportPayload = transportObj.getString("payload").hexToBytes()
        val transportExpected = transportObj.getString("ciphertext").hexToBytes()

        // Step 1: Initiator sends IK message 1 with WRONG remote static
        val ikInitiator = HandshakeState(
            pattern = HandshakePattern.IK,
            initiator = true,
            prologue = fallbackPrologue,
            s = NoiseKeyPair.fromPrivateKey(initStatic),
            rs = wrongRemoteStatic,
            keyPairGenerator = DeterministicKeyPairGenerator(initEphemeral)
        )
        val (ikMsg1, _) = ikInitiator.writeMessage(ikMsg1Payload)
        assertEquals(ikMsg1Expected.toHex(), ikMsg1.toHex(), "IK message 1 ciphertext mismatch")

        // Step 2: Extract initiator ephemeral
        val extractedEphemeral = ikMsg1.copyOfRange(0, DHLEN)
        assertContentEquals(initEphPub, extractedEphemeral)

        // Step 3: Set up XXfallback -- responder becomes initiator
        val fallbackInitiator = HandshakeState(
            pattern = HandshakePattern.XXfallback,
            initiator = true,
            prologue = fallbackPrologue,
            s = NoiseKeyPair.fromPrivateKey(respStatic),
            re = extractedEphemeral,
            keyPairGenerator = DeterministicKeyPairGenerator(respEphemeral)
        )

        // Step 4: Original initiator becomes XXfallback responder
        val fallbackResponder = HandshakeState(
            pattern = HandshakePattern.XXfallback,
            initiator = false,
            prologue = fallbackPrologue,
            s = NoiseKeyPair.fromPrivateKey(initStatic),
            e = NoiseKeyPair.fromPrivateKey(initEphemeral),
            keyPairGenerator = SequentialKeyPairGenerator(emptyList())
        )

        // Message 2: fallback initiator writes
        val (fbMsg2, _) = fallbackInitiator.writeMessage(fallbackMessages[0].payload)
        assertEquals(
            fallbackMessages[0].ciphertext.toHex(), fbMsg2.toHex(),
            "XXfallback message 2 ciphertext mismatch"
        )

        // Fallback responder reads message 2
        val (fbPayload2, _) = fallbackResponder.readMessage(fbMsg2)
        assertContentEquals(fallbackMessages[0].payload, fbPayload2)

        // Message 3: fallback responder writes
        val (fbMsg3, fbRespTransport) = fallbackResponder.writeMessage(fallbackMessages[1].payload)
        assertEquals(
            fallbackMessages[1].ciphertext.toHex(), fbMsg3.toHex(),
            "XXfallback message 3 ciphertext mismatch"
        )

        // Fallback initiator reads message 3
        val (_, fbInitTransport) = fallbackInitiator.readMessage(fbMsg3)

        assertNotNull(fbRespTransport)
        assertNotNull(fbInitTransport)

        // Handshake hash
        assertEquals(expectedHash.toHex(), fbInitTransport!!.handshakeHash.toHex())
        assertEquals(expectedHash.toHex(), fbRespTransport!!.handshakeHash.toHex())

        // Transport: fallback initiator (original responder) sends
        val transportCt = fbInitTransport.sendCipher.encryptWithAd(ByteArray(0), transportPayload)
        assertEquals(
            transportExpected.toHex(), transportCt.toHex(),
            "XXfallback transport ciphertext mismatch"
        )
    }

    // MARK: - Shared handshake runner

    private fun runHandshakeTest(
        suite: CipherSuite,
        pattern: HandshakePattern,
        initiatorStatic: ByteArray?,
        responderStatic: ByteArray?,
        initiatorRemoteStatic: ByteArray?,
        responderRemoteStatic: ByteArray?,
        psks: List<ByteArray> = emptyList(),
        handshakeMessages: List<TestMessage>,
        transportMessages: List<TestMessage>,
        expectedHandshakeHash: ByteArray,
        keys: JSONObject
    ) {
        val prologue = resolveKey(keys, "prologue")
        val initEphemeral = resolveKey(keys, "init_ephemeral")
        val respEphemeral = resolveKey(keys, "resp_ephemeral")

        val initS = initiatorStatic?.let { NoiseKeyPair.fromPrivateKey(it) }
        val respS = responderStatic?.let { NoiseKeyPair.fromPrivateKey(it) }

        val initiator = HandshakeState(
            pattern = pattern,
            initiator = true,
            suite = suite,
            prologue = prologue,
            s = initS,
            rs = initiatorRemoteStatic,
            psks = psks,
            keyPairGenerator = DeterministicKeyPairGenerator(initEphemeral)
        )
        val responder = HandshakeState(
            pattern = pattern,
            initiator = false,
            suite = suite,
            prologue = prologue,
            s = respS,
            rs = responderRemoteStatic,
            psks = psks,
            keyPairGenerator = DeterministicKeyPairGenerator(respEphemeral)
        )

        var initTransport: TransportState? = null
        var respTransport: TransportState? = null

        // Process handshake messages
        for ((i, msg) in handshakeMessages.withIndex()) {
            val isInitiatorSend = (i % 2 == 0)
            if (isInitiatorSend) {
                val (ct, transport) = initiator.writeMessage(msg.payload)
                assertEquals(msg.ciphertext.toHex(), ct.toHex(), "Handshake msg ${i+1} ciphertext mismatch")
                if (transport != null) initTransport = transport

                val (payload, rTransport) = responder.readMessage(ct)
                assertContentEquals(msg.payload, payload, "Handshake msg ${i+1} payload mismatch")
                if (rTransport != null) respTransport = rTransport
            } else {
                val (ct, transport) = responder.writeMessage(msg.payload)
                assertEquals(msg.ciphertext.toHex(), ct.toHex(), "Handshake msg ${i+1} ciphertext mismatch")
                if (transport != null) respTransport = transport

                val (payload, iTransport) = initiator.readMessage(ct)
                assertContentEquals(msg.payload, payload, "Handshake msg ${i+1} payload mismatch")
                if (iTransport != null) initTransport = iTransport
            }
        }

        assertNotNull(initTransport, "Initiator handshake did not complete")
        assertNotNull(respTransport, "Responder handshake did not complete")

        assertEquals(expectedHandshakeHash.toHex(), initTransport!!.handshakeHash.toHex(), "Initiator handshake hash mismatch")
        assertEquals(expectedHandshakeHash.toHex(), respTransport!!.handshakeHash.toHex(), "Responder handshake hash mismatch")

        // Process transport messages
        for ((i, msg) in transportMessages.withIndex()) {
            val isInitiatorSend = ((handshakeMessages.size + i) % 2 == 0)
            if (isInitiatorSend) {
                val ct = initTransport!!.sendCipher.encryptWithAd(ByteArray(0), msg.payload)
                assertEquals(msg.ciphertext.toHex(), ct.toHex(), "Transport msg ${i+1} ciphertext mismatch")
                val pt = respTransport!!.receiveCipher.decryptWithAd(ByteArray(0), ct)
                assertContentEquals(msg.payload, pt, "Transport msg ${i+1} payload mismatch")
            } else {
                val ct = respTransport!!.sendCipher.encryptWithAd(ByteArray(0), msg.payload)
                assertEquals(msg.ciphertext.toHex(), ct.toHex(), "Transport msg ${i+1} ciphertext mismatch")
                val pt = initTransport!!.receiveCipher.decryptWithAd(ByteArray(0), ct)
                assertContentEquals(msg.payload, pt, "Transport msg ${i+1} payload mismatch")
            }
        }
    }
}
