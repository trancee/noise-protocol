package com.noise.protocol.state

import com.noise.protocol.crypto.CipherSuite

/**
 * Wraps CipherState with chaining key and handshake hash.
 */
class SymmetricState(private val suite: CipherSuite = CipherSuite.NOISE_25519_CHACHAPOLY_SHA256) {
    private var ck: ByteArray = ByteArray(0)
    private var h: ByteArray = ByteArray(0)
    private val cipherState = CipherState(suite)

    /** True if the handshake uses PSK mode (modifies "e" token processing). */
    var hasPSK: Boolean = false

    fun initializeSymmetric(protocolName: String) {
        val nameBytes = protocolName.toByteArray(Charsets.UTF_8)
        h = if (nameBytes.size <= suite.hashlen) {
            nameBytes + ByteArray(suite.hashlen - nameBytes.size)
        } else {
            suite.hash(nameBytes)
        }
        ck = h.copyOf()
        cipherState.initializeKey(null)
    }

    fun mixKey(inputKeyMaterial: ByteArray) {
        val outputs = suite.hkdf(ck, inputKeyMaterial, 2)
        ck = outputs[0]
        var tempK = outputs[1]
        if (suite.hashlen > 32) {
            tempK = tempK.copyOfRange(0, 32)
        }
        cipherState.initializeKey(tempK)
    }

    fun mixHash(data: ByteArray) {
        h = suite.hash(h + data)
    }

    /** Used for PSK mode. Mixes key material into ck, h, and cipher key. */
    fun mixKeyAndHash(inputKeyMaterial: ByteArray) {
        val outputs = suite.hkdf(ck, inputKeyMaterial, 3)
        ck = outputs[0]
        mixHash(outputs[1])
        var tempK = outputs[2]
        if (suite.hashlen > 32) {
            tempK = tempK.copyOfRange(0, 32)
        }
        cipherState.initializeKey(tempK)
    }

    fun getHandshakeHash(): ByteArray = h.copyOf()

    /** Encrypts plaintext using h as AD, then mixes ciphertext into h. */
    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ciphertext = cipherState.encryptWithAd(h, plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    /** Decrypts ciphertext using h as AD, then mixes ciphertext into h. */
    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val plaintext = cipherState.decryptWithAd(h, ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    /**
     * Splits into two CipherStates for transport.
     * c1 encrypts initiator→responder, c2 encrypts responder→initiator.
     */
    fun split(): Pair<CipherState, CipherState> {
        val outputs = suite.hkdf(ck, ByteArray(0), 2)
        var tempK1 = outputs[0]
        var tempK2 = outputs[1]
        if (suite.hashlen > 32) {
            tempK1 = tempK1.copyOfRange(0, 32)
            tempK2 = tempK2.copyOfRange(0, 32)
        }
        val c1 = CipherState(suite)
        val c2 = CipherState(suite)
        c1.initializeKey(tempK1)
        c2.initializeKey(tempK2)
        return c1 to c2
    }

    val hasKey: Boolean get() = cipherState.hasKey
}
