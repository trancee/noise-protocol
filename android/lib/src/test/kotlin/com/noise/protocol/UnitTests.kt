package com.noise.protocol

import com.noise.protocol.crypto.*
import com.noise.protocol.pattern.HandshakePattern
import com.noise.protocol.pattern.Token
import com.noise.protocol.state.CipherState
import com.noise.protocol.state.HandshakeState
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

// MARK: - CipherState Tests

class CipherStateTests {

    @Test
    fun testUnkeyedPassthrough() {
        val cs = CipherState()
        val plaintext = "hello world".toByteArray()
        val result = cs.encryptWithAd(ByteArray(0), plaintext)
        assertContentEquals(plaintext, result, "Unkeyed encrypt should pass through")
    }

    @Test
    fun testKeyedEncryptDecrypt() {
        val key = ByteArray(32) { it.toByte() }
        val cs = CipherState()
        cs.initializeKey(key)
        val ad = "additional data".toByteArray()
        val plaintext = "secret message".toByteArray()
        val ciphertext = cs.encryptWithAd(ad, plaintext)
        assertTrue(ciphertext.size == plaintext.size + 16, "Ciphertext should include 16-byte tag")

        val cs2 = CipherState()
        cs2.initializeKey(key)
        val decrypted = cs2.decryptWithAd(ad, ciphertext)
        assertContentEquals(plaintext, decrypted)
    }

    @Test
    fun testNonceIncrement() {
        val key = ByteArray(32) { it.toByte() }
        val cs = CipherState()
        cs.initializeKey(key)
        assertEquals(0L, cs.getNonce())
        cs.encryptWithAd(ByteArray(0), "test".toByteArray())
        assertEquals(1L, cs.getNonce())
        cs.encryptWithAd(ByteArray(0), "test".toByteArray())
        assertEquals(2L, cs.getNonce())
    }

    @Test
    fun testDecryptionFailureDoesNotIncrementNonce() {
        val key1 = ByteArray(32) { it.toByte() }
        val key2 = ByteArray(32) { (it + 1).toByte() }
        val csEnc = CipherState()
        csEnc.initializeKey(key1)
        val ct = csEnc.encryptWithAd(ByteArray(0), "test".toByteArray())

        val csDec = CipherState()
        csDec.initializeKey(key2) // wrong key
        assertEquals(0L, csDec.getNonce())
        assertThrows<NoiseException.DecryptionFailed> {
            csDec.decryptWithAd(ByteArray(0), ct)
        }
        assertEquals(0L, csDec.getNonce(), "Nonce should not increment on failure")
    }

    @Test
    fun testRekey() {
        val key = ByteArray(32) { it.toByte() }
        val cs1 = CipherState()
        cs1.initializeKey(key)
        val cs2 = CipherState()
        cs2.initializeKey(key)

        cs1.rekey()
        cs2.rekey()

        val plaintext = "after rekey".toByteArray()
        val ct = cs1.encryptWithAd(ByteArray(0), plaintext)
        val pt = cs2.decryptWithAd(ByteArray(0), ct)
        assertContentEquals(plaintext, pt, "Both sides should derive same rekey")
    }
}

// MARK: - Round-trip Handshake Tests

class RoundTripTests {

    @Test
    fun testNNRoundTrip() {
        val initiator = HandshakeState(
            pattern = HandshakePattern.NN,
            initiator = true,
            prologue = ByteArray(0)
        )
        val responder = HandshakeState(
            pattern = HandshakePattern.NN,
            initiator = false,
            prologue = ByteArray(0)
        )

        val (msg1, _) = initiator.writeMessage("hello".toByteArray())
        val (payload1, _) = responder.readMessage(msg1)
        assertContentEquals("hello".toByteArray(), payload1)

        val (msg2, respTransport) = responder.writeMessage("world".toByteArray())
        val (payload2, initTransport) = initiator.readMessage(msg2)
        assertContentEquals("world".toByteArray(), payload2)

        assertNotNull(initTransport)
        assertNotNull(respTransport)

        // Transport phase
        val ct = initTransport!!.sendCipher.encryptWithAd(ByteArray(0), "transport".toByteArray())
        val pt = respTransport!!.receiveCipher.decryptWithAd(ByteArray(0), ct)
        assertContentEquals("transport".toByteArray(), pt)
    }

    @Test
    fun testXXRoundTrip() {
        val initiator = HandshakeState(
            pattern = HandshakePattern.XX,
            initiator = true,
            prologue = ByteArray(0),
            s = NoiseKeyPair.generate()
        )
        val responder = HandshakeState(
            pattern = HandshakePattern.XX,
            initiator = false,
            prologue = ByteArray(0),
            s = NoiseKeyPair.generate()
        )

        val (msg1, _) = initiator.writeMessage("msg1".toByteArray())
        val (p1, _) = responder.readMessage(msg1)
        assertContentEquals("msg1".toByteArray(), p1)

        val (msg2, _) = responder.writeMessage("msg2".toByteArray())
        val (p2, _) = initiator.readMessage(msg2)
        assertContentEquals("msg2".toByteArray(), p2)

        val (msg3, respT) = initiator.writeMessage("msg3".toByteArray())
        val (p3, initT) = responder.readMessage(msg3)
        assertContentEquals("msg3".toByteArray(), p3)

        assertNotNull(initT)
        assertNotNull(respT)

        // Bidirectional transport
        val ct1 = respT!!.sendCipher.encryptWithAd(ByteArray(0), "from init".toByteArray())
        val pt1 = initT!!.receiveCipher.decryptWithAd(ByteArray(0), ct1)
        assertContentEquals("from init".toByteArray(), pt1)

        val ct2 = initT.sendCipher.encryptWithAd(ByteArray(0), "from resp".toByteArray())
        val pt2 = respT.receiveCipher.decryptWithAd(ByteArray(0), ct2)
        assertContentEquals("from resp".toByteArray(), pt2)
    }

    @Test
    fun testIKRoundTrip() {
        val respKp = NoiseKeyPair.generate()
        val initiator = HandshakeState(
            pattern = HandshakePattern.IK,
            initiator = true,
            prologue = ByteArray(0),
            s = NoiseKeyPair.generate(),
            rs = respKp.publicKey
        )
        val responder = HandshakeState(
            pattern = HandshakePattern.IK,
            initiator = false,
            prologue = ByteArray(0),
            s = respKp
        )

        val (msg1, _) = initiator.writeMessage()
        val (_, _) = responder.readMessage(msg1)

        val (msg2, respT) = responder.writeMessage()
        val (_, initT) = initiator.readMessage(msg2)

        assertNotNull(initT)
        assertNotNull(respT)
    }

    @Test
    fun testEmptyPayloadHandshake() {
        val initiator = HandshakeState(
            pattern = HandshakePattern.NN,
            initiator = true,
            prologue = ByteArray(0)
        )
        val responder = HandshakeState(
            pattern = HandshakePattern.NN,
            initiator = false,
            prologue = ByteArray(0)
        )

        val (msg1, _) = initiator.writeMessage()
        val (p1, _) = responder.readMessage(msg1)
        assertEquals(0, p1.size)

        val (msg2, _) = responder.writeMessage()
        val (p2, _) = initiator.readMessage(msg2)
        assertEquals(0, p2.size)
    }
}

// MARK: - DH Tests

class DHTests {

    @Test
    fun testKeyPairGeneration() {
        val kp = NoiseKeyPair.generate()
        assertEquals(32, kp.publicKey.size)
    }

    @Test
    fun testDeterministicKeyPair() {
        val privKey = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a".hexToBytes()
        val kp = NoiseKeyPair.fromPrivateKey(privKey)
        val expectedPub = "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944".hexToBytes()
        assertContentEquals(expectedPub, kp.publicKey)
    }

    @Test
    fun testDHAgreement() {
        val kp1 = NoiseKeyPair.generate()
        val kp2 = NoiseKeyPair.generate()
        val shared1 = kp1.dh(kp2.publicKey)
        val shared2 = kp2.dh(kp1.publicKey)
        assertContentEquals(shared1, shared2, "DH should be commutative")
        assertEquals(32, shared1.size)
    }
}

// MARK: - Error Handling Tests

class ErrorHandlingTests {

    @Test
    fun testWriteAfterComplete() {
        val initiator = HandshakeState(
            pattern = HandshakePattern.NN,
            initiator = true,
            prologue = ByteArray(0)
        )
        val responder = HandshakeState(
            pattern = HandshakePattern.NN,
            initiator = false,
            prologue = ByteArray(0)
        )

        val (msg1, _) = initiator.writeMessage()
        responder.readMessage(msg1)
        val (msg2, _) = responder.writeMessage()
        initiator.readMessage(msg2)

        assertThrows<NoiseException.HandshakeAlreadyComplete> {
            initiator.writeMessage()
        }
    }

    @Test
    fun testReadOnWriteTurn() {
        val initiator = HandshakeState(
            pattern = HandshakePattern.NN,
            initiator = true,
            prologue = ByteArray(0)
        )
        assertThrows<NoiseException> {
            initiator.readMessage(ByteArray(32))
        }
    }

    @Test
    fun testDecryptionFailure() {
        val key = ByteArray(32) { it.toByte() }
        val cs = CipherState()
        cs.initializeKey(key)
        assertThrows<NoiseException.DecryptionFailed> {
            cs.decryptWithAd(ByteArray(0), ByteArray(20))
        }
    }

    @Test
    fun testUnknownPattern() {
        assertThrows<NoiseException.UnknownPattern> {
            HandshakePattern.named("NotAPattern")
        }
    }
}

// MARK: - Pattern Definition Tests

class PatternDefinitionTests {

    @Test
    fun testNNDefinition() {
        val p = HandshakePattern.NN
        assertEquals(2, p.messagePatterns.size)
        assertEquals(listOf(Token.E), p.messagePatterns[0])
        assertEquals(listOf(Token.E, Token.EE), p.messagePatterns[1])
        assertTrue(p.initiatorPreMessage.isEmpty())
        assertTrue(p.responderPreMessage.isEmpty())
    }

    @Test
    fun testXXDefinition() {
        val p = HandshakePattern.XX
        assertEquals(3, p.messagePatterns.size)
        assertEquals(listOf(Token.E), p.messagePatterns[0])
        assertEquals(listOf(Token.E, Token.EE, Token.S, Token.ES), p.messagePatterns[1])
        assertEquals(listOf(Token.S, Token.SE), p.messagePatterns[2])
    }

    @Test
    fun testIKDefinition() {
        val p = HandshakePattern.IK
        assertEquals(2, p.messagePatterns.size)
        assertEquals(listOf(Token.E, Token.ES, Token.S, Token.SS), p.messagePatterns[0])
        assertEquals(listOf(Token.E, Token.EE, Token.SE), p.messagePatterns[1])
        assertEquals(listOf(Token.S), p.responderPreMessage)
    }

    @Test
    fun testNKpsk0Definition() {
        val p = HandshakePattern.NKpsk0
        assertEquals(listOf(Token.PSK, Token.E, Token.ES), p.messagePatterns[0])
        assertEquals(listOf(Token.E, Token.EE), p.messagePatterns[1])
        assertEquals(listOf(Token.S), p.responderPreMessage)
    }

    @Test
    fun testIKpsk2Definition() {
        val p = HandshakePattern.IKpsk2
        assertEquals(listOf(Token.E, Token.ES, Token.S, Token.SS), p.messagePatterns[0])
        assertEquals(listOf(Token.E, Token.EE, Token.SE, Token.PSK), p.messagePatterns[1])
        assertEquals(listOf(Token.S), p.responderPreMessage)
    }

    @Test
    fun testXXfallbackDefinition() {
        val p = HandshakePattern.XXfallback
        assertEquals(2, p.messagePatterns.size)
        assertEquals(listOf(Token.E), p.responderPreMessage)
    }

    @Test
    fun testNamedPatternLookup() {
        assertNotNull(HandshakePattern.named("NN"))
        assertNotNull(HandshakePattern.named("XX"))
        assertNotNull(HandshakePattern.named("IK"))
        assertNotNull(HandshakePattern.named("XXfallback"))
        assertThrows<NoiseException.UnknownPattern> {
            HandshakePattern.named("ZZ")
        }
    }

    @Test
    fun testAllPatternsExist() {
        val expectedPatterns = listOf(
            "N", "K", "X",
            "NN", "NK", "NX", "XN", "XK", "XX", "KN", "KK", "KX", "IN", "IK", "IX",
            "XXfallback", "NKpsk0", "IKpsk2"
        )
        for (name in expectedPatterns) {
            assertNotNull(HandshakePattern.all[name], "Pattern $name should exist")
        }
    }
}

// MARK: - Channel Binding Tests

class ChannelBindingTests {

    @Test
    fun testHandshakeHashMatches() {
        val initKp = NoiseKeyPair.generate()
        val respKp = NoiseKeyPair.generate()

        val initiator = HandshakeState(
            pattern = HandshakePattern.XX,
            initiator = true,
            prologue = ByteArray(0),
            s = initKp
        )
        val responder = HandshakeState(
            pattern = HandshakePattern.XX,
            initiator = false,
            prologue = ByteArray(0),
            s = respKp
        )

        val (m1, _) = initiator.writeMessage()
        responder.readMessage(m1)
        val (m2, _) = responder.writeMessage()
        initiator.readMessage(m2)
        val (m3, respT) = initiator.writeMessage()
        val (_, initT) = responder.readMessage(m3)

        assertNotNull(initT)
        assertNotNull(respT)
        assertContentEquals(
            initT!!.handshakeHash,
            respT!!.handshakeHash,
            "Both sides should have same handshake hash"
        )
    }

    @Test
    fun testRemoteStaticKeyExchange() {
        val initKp = NoiseKeyPair.generate()
        val respKp = NoiseKeyPair.generate()

        val initiator = HandshakeState(
            pattern = HandshakePattern.XX,
            initiator = true,
            prologue = ByteArray(0),
            s = initKp
        )
        val responder = HandshakeState(
            pattern = HandshakePattern.XX,
            initiator = false,
            prologue = ByteArray(0),
            s = respKp
        )

        val (m1, _) = initiator.writeMessage()
        responder.readMessage(m1)
        val (m2, _) = responder.writeMessage()
        initiator.readMessage(m2)
        val (m3, respT) = initiator.writeMessage()
        val (_, initT) = responder.readMessage(m3)

        assertNotNull(initT)
        assertNotNull(respT)
        assertContentEquals(respKp.publicKey, respT!!.remoteStaticKey, "Initiator should know responder's static key")
        assertContentEquals(initKp.publicKey, initT!!.remoteStaticKey, "Responder should know initiator's static key")
    }
}

// MARK: - Crypto Primitives Tests

class CryptoPrimitivesTests {

    @Test
    fun testSHA256KnownVector() {
        val input = "abc".toByteArray()
        val expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".hexToBytes()
        assertContentEquals(expected, NoiseHash.hash(input))
    }

    @Test
    fun testHKDF2Outputs() {
        val ck = ByteArray(32) { it.toByte() }
        val ikm = ByteArray(32) { (it + 32).toByte() }
        val outputs = NoiseHash.hkdf(ck, ikm, 2)
        assertEquals(2, outputs.size)
        assertEquals(32, outputs[0].size)
        assertEquals(32, outputs[1].size)
    }

    @Test
    fun testHKDF3Outputs() {
        val ck = ByteArray(32) { it.toByte() }
        val ikm = ByteArray(32) { (it + 32).toByte() }
        val outputs = NoiseHash.hkdf(ck, ikm, 3)
        assertEquals(3, outputs.size)
        for (o in outputs) assertEquals(32, o.size)
    }

    @Test
    fun testChaCha20Poly1305RoundTrip() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = 42L
        val ad = "test".toByteArray()
        val plaintext = "hello world!".toByteArray()
        val ct = NoiseCipher.encrypt(key, nonce, ad, plaintext)
        assertEquals(plaintext.size + 16, ct.size)
        val pt = NoiseCipher.decrypt(key, nonce, ad, ct)
        assertContentEquals(plaintext, pt)
    }
}
