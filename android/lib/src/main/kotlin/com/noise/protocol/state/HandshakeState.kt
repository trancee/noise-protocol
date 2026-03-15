package com.noise.protocol.state

import com.noise.protocol.NoiseException
import com.noise.protocol.crypto.CipherSuite
import com.noise.protocol.crypto.NoiseKeyPair
import com.noise.protocol.crypto.NoiseKeyPairGenerator
import com.noise.protocol.crypto.RandomKeyPairGenerator
import com.noise.protocol.pattern.HandshakePattern
import com.noise.protocol.pattern.Token

/**
 * Result of a completed handshake: two CipherStates for transport encryption.
 */
data class TransportState(
    /** Encrypts messages sent by this party. */
    val sendCipher: CipherState,
    /** Decrypts messages received by this party. */
    val receiveCipher: CipherState,
    /** Handshake hash for channel binding. */
    val handshakeHash: ByteArray,
    /** Remote party's static public key (if authenticated during handshake). */
    val remoteStaticKey: ByteArray?
)

/**
 * Top-level Noise handshake state machine.
 * Processes handshake messages according to a pattern, then produces transport CipherStates.
 */
class HandshakeState(
    pattern: HandshakePattern,
    private val initiator: Boolean,
    private val suite: CipherSuite = CipherSuite.NOISE_25519_CHACHAPOLY_SHA256,
    prologue: ByteArray = ByteArray(0),
    private var s: NoiseKeyPair? = null,
    private var e: NoiseKeyPair? = null,
    private var rs: ByteArray? = null,
    private var re: ByteArray? = null,
    private val psks: List<ByteArray> = emptyList(),
    private val keyPairGenerator: NoiseKeyPairGenerator = RandomKeyPairGenerator()
) {
    private val symmetricState = SymmetricState(suite)
    private val messagePatterns: List<List<Token>> = pattern.messagePatterns
    private var messageIndex: Int = 0
    private var pskIndex: Int = 0
    private var isComplete: Boolean = false

    init {
        val hasPSK = pattern.messagePatterns.any { Token.PSK in it }
        symmetricState.hasPSK = hasPSK

        val protocolName = suite.protocolName(pattern.name)
        symmetricState.initializeSymmetric(protocolName)
        symmetricState.mixHash(prologue)

        // Process pre-messages
        for (token in pattern.initiatorPreMessage) {
            when (token) {
                Token.S -> {
                    if (initiator) s?.let { symmetricState.mixHash(it.publicKey) }
                    else rs?.let { symmetricState.mixHash(it) }
                }
                Token.E -> {
                    if (initiator) e?.let { symmetricState.mixHash(it.publicKey) }
                    else re?.let { symmetricState.mixHash(it) }
                }
                else -> {}
            }
        }
        for (token in pattern.responderPreMessage) {
            when (token) {
                Token.S -> {
                    if (!initiator) s?.let { symmetricState.mixHash(it.publicKey) }
                    else rs?.let { symmetricState.mixHash(it) }
                }
                Token.E -> {
                    if (!initiator) e?.let { symmetricState.mixHash(it.publicKey) }
                    else re?.let { symmetricState.mixHash(it) }
                }
                else -> {}
            }
        }
    }

    /** True if it's this party's turn to write (send) a message. */
    val isMySend: Boolean
        get() = (messageIndex % 2 == 0) == initiator

    /** The remote party's static public key, if received during the handshake. */
    val remoteStaticPublicKey: ByteArray? get() = rs

    /**
     * Write a handshake message with optional payload.
     * Returns the message bytes and, if the handshake is now complete, a TransportState.
     */
    fun writeMessage(payload: ByteArray = ByteArray(0)): Pair<ByteArray, TransportState?> {
        if (isComplete) throw NoiseException.HandshakeAlreadyComplete()
        if (messageIndex >= messagePatterns.size) throw NoiseException.HandshakeAlreadyComplete()
        if (!isMySend) throw NoiseException.NotYourTurn()

        val pattern = messagePatterns[messageIndex]
        messageIndex++
        val output = java.io.ByteArrayOutputStream(256)

        for (token in pattern) {
            when (token) {
                Token.E -> {
                    if (e == null) e = keyPairGenerator.generate()
                    output.write(e!!.publicKey)
                    symmetricState.mixHash(e!!.publicKey)
                    if (symmetricState.hasPSK) {
                        symmetricState.mixKey(e!!.publicKey)
                    }
                }
                Token.S -> {
                    val encrypted = symmetricState.encryptAndHash(s!!.publicKey)
                    output.write(encrypted)
                }
                Token.EE -> symmetricState.mixKey(e!!.dh(re!!))
                Token.ES -> {
                    if (initiator) symmetricState.mixKey(e!!.dh(rs!!))
                    else symmetricState.mixKey(s!!.dh(re!!))
                }
                Token.SE -> {
                    if (initiator) symmetricState.mixKey(s!!.dh(re!!))
                    else symmetricState.mixKey(e!!.dh(rs!!))
                }
                Token.SS -> symmetricState.mixKey(s!!.dh(rs!!))
                Token.PSK -> {
                    if (pskIndex >= psks.size) throw NoiseException.MissingKey("PSK at index $pskIndex")
                    symmetricState.mixKeyAndHash(psks[pskIndex])
                    pskIndex++
                }
            }
        }

        val encryptedPayload = symmetricState.encryptAndHash(payload)
        output.write(encryptedPayload)
        val buffer = output.toByteArray()

        return if (messageIndex >= messagePatterns.size) {
            buffer to finalize()
        } else {
            buffer to null
        }
    }

    /**
     * Read a handshake message from the remote party.
     * Returns the decrypted payload and, if the handshake is now complete, a TransportState.
     */
    fun readMessage(message: ByteArray): Pair<ByteArray, TransportState?> {
        if (isComplete) throw NoiseException.HandshakeAlreadyComplete()
        if (messageIndex >= messagePatterns.size) throw NoiseException.HandshakeAlreadyComplete()
        if (isMySend) throw NoiseException.NotYourTurn()

        val pattern = messagePatterns[messageIndex]
        messageIndex++
        var offset = 0

        for (token in pattern) {
            when (token) {
                Token.E -> {
                    if (message.size < offset + suite.dhlen) throw NoiseException.InvalidMessage()
                    re = message.copyOfRange(offset, offset + suite.dhlen)
                    offset += suite.dhlen
                    symmetricState.mixHash(re!!)
                    if (symmetricState.hasPSK) {
                        symmetricState.mixKey(re!!)
                    }
                }
                Token.S -> {
                    val len = if (symmetricState.hasKey) suite.dhlen + 16 else suite.dhlen
                    if (message.size < offset + len) throw NoiseException.InvalidMessage()
                    val temp = message.copyOfRange(offset, offset + len)
                    offset += len
                    rs = symmetricState.decryptAndHash(temp)
                }
                Token.EE -> symmetricState.mixKey(e!!.dh(re!!))
                Token.ES -> {
                    if (initiator) symmetricState.mixKey(e!!.dh(rs!!))
                    else symmetricState.mixKey(s!!.dh(re!!))
                }
                Token.SE -> {
                    if (initiator) symmetricState.mixKey(s!!.dh(re!!))
                    else symmetricState.mixKey(e!!.dh(rs!!))
                }
                Token.SS -> symmetricState.mixKey(s!!.dh(rs!!))
                Token.PSK -> {
                    if (pskIndex >= psks.size) throw NoiseException.MissingKey("PSK at index $pskIndex")
                    symmetricState.mixKeyAndHash(psks[pskIndex])
                    pskIndex++
                }
            }
        }

        val remaining = message.copyOfRange(offset, message.size)
        val payload = symmetricState.decryptAndHash(remaining)

        return if (messageIndex >= messagePatterns.size) {
            payload to finalize()
        } else {
            payload to null
        }
    }

    private fun finalize(): TransportState {
        isComplete = true
        val (c1, c2) = symmetricState.split()
        val handshakeHash = symmetricState.getHandshakeHash()
        return if (initiator) {
            TransportState(c1, c2, handshakeHash, rs)
        } else {
            TransportState(c2, c1, handshakeHash, rs)
        }
    }
}
