package com.noise.protocol

import com.noise.protocol.crypto.NoiseKeyPair
import com.noise.protocol.crypto.NoiseKeyPairGenerator
import com.noise.protocol.crypto.DeterministicKeyPairGenerator
import com.noise.protocol.crypto.DHLEN
import com.noise.protocol.pattern.HandshakePattern
import com.noise.protocol.state.HandshakeState
import com.noise.protocol.state.TransportState
import org.json.JSONObject
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

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
        private val json: JSONObject = run {
            val stream = TestVectorTests::class.java.getResourceAsStream(
                "/noise_25519_ChaChaPoly_SHA256.json"
            ) ?: error("Test vector JSON not found on classpath")
            JSONObject(stream.bufferedReader().readText())
        }

        private val keys: JSONObject = json.getJSONObject("keys")

        /** Resolve a key reference (string name) to its hex bytes via the keys object. */
        fun resolveKey(keyName: String): ByteArray = keys.getString(keyName).hexToBytes()

        /** Resolve a nullable key field: null in JSON → null, otherwise lookup in keys. */
        fun resolveOptionalKey(vector: JSONObject, field: String): ByteArray? {
            if (vector.isNull(field)) return null
            return resolveKey(vector.getString(field))
        }

        /** Parse handshake or transport messages from a JSONArray of {payload, ciphertext}. */
        fun parseMessages(array: org.json.JSONArray): List<TestMessage> =
            (0 until array.length()).map { i ->
                val obj = array.getJSONObject(i)
                TestMessage(
                    payload = obj.getString("payload").hexToBytes(),
                    ciphertext = obj.getString("ciphertext").hexToBytes()
                )
            }

        /** Find a standard vector by pattern name. */
        fun findVector(pattern: String): JSONObject {
            val vectors = json.getJSONArray("vectors")
            for (i in 0 until vectors.length()) {
                val v = vectors.getJSONObject(i)
                if (v.getString("pattern") == pattern) return v
            }
            error("No vector found for pattern: $pattern")
        }

        /** Find a fallback vector by pattern name. */
        fun findFallbackVector(pattern: String): JSONObject {
            val vectors = json.getJSONArray("fallback_vectors")
            for (i in 0 until vectors.length()) {
                val v = vectors.getJSONObject(i)
                if (v.getString("pattern") == pattern) return v
            }
            error("No fallback vector found for pattern: $pattern")
        }

        /** Resolve the PSK list from a vector's "psks" array of key name strings. */
        fun resolvePsks(vector: JSONObject): List<ByteArray> {
            val arr = vector.getJSONArray("psks")
            return (0 until arr.length()).map { resolveKey(arr.getString(it)) }
        }
    }

    // MARK: - Standard pattern tests

    @Test
    fun testNN() = runStandardVectorTest("NN")

    @Test
    fun testNK() = runStandardVectorTest("NK")

    @Test
    fun testXX() = runStandardVectorTest("XX")

    @Test
    fun testIK() = runStandardVectorTest("IK")

    @Test
    fun testNKpsk0() = runStandardVectorTest("NKpsk0")

    @Test
    fun testIKpsk2() = runStandardVectorTest("IKpsk2")

    private fun runStandardVectorTest(patternName: String) {
        val vector = findVector(patternName)

        val initiatorStatic = resolveOptionalKey(vector, "init_static")
        val responderStatic = resolveOptionalKey(vector, "resp_static")
        val initiatorRemoteStatic = resolveOptionalKey(vector, "init_remote_static")
        val responderRemoteStatic = resolveOptionalKey(vector, "resp_remote_static")
        val psks = resolvePsks(vector)
        val handshakeMessages = parseMessages(vector.getJSONArray("handshake_messages"))
        val transportMessages = parseMessages(vector.getJSONArray("transport_messages"))
        val expectedHash = vector.getString("handshake_hash").hexToBytes()

        runHandshakeTest(
            pattern = HandshakePattern.named(patternName),
            initiatorStatic = initiatorStatic,
            responderStatic = responderStatic,
            initiatorRemoteStatic = initiatorRemoteStatic,
            responderRemoteStatic = responderRemoteStatic,
            psks = psks,
            handshakeMessages = handshakeMessages,
            transportMessages = transportMessages,
            expectedHandshakeHash = expectedHash
        )
    }

    // MARK: XXfallback

    @Test
    fun testXXfallback() {
        val vector = findFallbackVector("XXfallback")
        val initEphemeral = resolveKey("init_ephemeral")
        val respEphemeral = resolveKey("resp_ephemeral")
        val initStatic = resolveKey("init_static")
        val respStatic = resolveKey("resp_static")
        val initEphPub = resolveKey("init_eph_pub")

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

        // Step 3: Set up XXfallback — responder becomes initiator
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
        pattern: HandshakePattern,
        initiatorStatic: ByteArray?,
        responderStatic: ByteArray?,
        initiatorRemoteStatic: ByteArray?,
        responderRemoteStatic: ByteArray?,
        psks: List<ByteArray> = emptyList(),
        handshakeMessages: List<TestMessage>,
        transportMessages: List<TestMessage>,
        expectedHandshakeHash: ByteArray
    ) {
        val prologue = resolveKey("prologue")
        val initEphemeral = resolveKey("init_ephemeral")
        val respEphemeral = resolveKey("resp_ephemeral")

        val initS = initiatorStatic?.let { NoiseKeyPair.fromPrivateKey(it) }
        val respS = responderStatic?.let { NoiseKeyPair.fromPrivateKey(it) }

        val initiator = HandshakeState(
            pattern = pattern,
            initiator = true,
            prologue = prologue,
            s = initS,
            rs = initiatorRemoteStatic,
            psks = psks,
            keyPairGenerator = DeterministicKeyPairGenerator(initEphemeral)
        )
        val responder = HandshakeState(
            pattern = pattern,
            initiator = false,
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
