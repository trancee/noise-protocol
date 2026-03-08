package noise.protocol.core

class HandshakeSession {
    private var state: HandshakeState? = null

    fun initialize(handshakeState: HandshakeState) {
        state = handshakeState
    }

    fun initialize(
        pattern: HandshakePattern,
        role: HandshakeRole,
        cryptoSuite: NoiseCryptoSuite,
        protocolName: String = pattern.protocolName,
        prologue: ByteArray = EMPTY_BYTE_ARRAY,
        localStatic: NoiseKeyPair? = null,
        localEphemeral: NoiseKeyPair? = null,
        remoteStatic: ByteArray? = null,
        remoteEphemeral: ByteArray? = null,
        ephemeralKeyGenerator: () -> NoiseKeyPair = cryptoSuite.diffieHellman::generateKeyPair
    ) {
        state = HandshakeState.initialize(
            pattern = pattern,
            role = role,
            cryptoSuite = cryptoSuite,
            protocolName = protocolName,
            prologue = prologue,
            localStatic = localStatic,
            localEphemeral = localEphemeral,
            remoteStatic = remoteStatic,
            remoteEphemeral = remoteEphemeral,
            ephemeralKeyGenerator = ephemeralKeyGenerator
        )
    }

    fun expectedDirection(): MessageDirection? = requireState().expectedDirection()

    fun isComplete(): Boolean = requireState().isComplete()

    fun handshakeHash(): ByteArray = requireState().handshakeHash()

    fun writeMessageFrame(payload: ByteArray = EMPTY_BYTE_ARRAY): HandshakeMessage {
        return requireState().writeMessage(payload)
    }

    fun readMessageFrame(message: HandshakeMessage): ByteArray {
        return requireState().readMessage(message)
    }

    fun writeMessage(payload: ByteArray = EMPTY_BYTE_ARRAY): ByteArray {
        return writeMessageFrame(payload).encoded()
    }

    fun readMessage(message: ByteArray): ByteArray {
        val currentState = requireState()
        val direction = currentState.expectedDirection()
            ?: error("Handshake already complete.")
        val expectedTokens = currentState.expectedTokenPayloads()
            ?: error("Handshake already complete.")
        val decoded = HandshakeMessage.decode(
            direction = direction,
            expectedTokens = expectedTokens,
            encoded = message
        )
        return currentState.readMessage(decoded)
    }

    fun splitTransportStates(): Pair<CipherState, CipherState> {
        return requireState().splitTransportStates()
    }

    private fun requireState(): HandshakeState {
        return state ?: error("Handshake session is not initialized.")
    }

    private companion object {
        val EMPTY_BYTE_ARRAY = ByteArray(0)
    }
}