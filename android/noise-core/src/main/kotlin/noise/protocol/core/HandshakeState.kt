package noise.protocol.core

data class HandshakeTokenValue(
    val token: HandshakeToken,
    val data: ByteArray
)

data class HandshakeMessage(
    val direction: MessageDirection,
    val tokenValues: List<HandshakeTokenValue>,
    val payload: ByteArray
) {
    fun encodedSize(): Int {
        require(tokenValues.size <= MAX_SEGMENT_COUNT) {
            "Handshake message contains too many token payload segments."
        }
        require(payload.size <= MAX_SEGMENT_LENGTH) {
            "Handshake message payload exceeds UInt16 maximum."
        }

        val size = 2 + tokenValues.sumOf { tokenValue ->
            require(tokenValue.data.size <= MAX_SEGMENT_LENGTH) {
                "Handshake token payload exceeds UInt16 maximum."
            }
            2 + tokenValue.data.size
        } + 2 + payload.size

        require(size <= MAX_ENCODED_SIZE) {
            "Handshake message exceeds the Noise maximum message size of $MAX_ENCODED_SIZE bytes."
        }
        return size
    }

    fun encoded(): ByteArray {
        val size = encodedSize()
        val encoded = ByteArray(size)
        var offset = 0

        fun writeUInt16(value: Int) {
            encoded[offset] = ((value ushr 8) and 0xFF).toByte()
            encoded[offset + 1] = (value and 0xFF).toByte()
            offset += 2
        }

        writeUInt16(tokenValues.size)
        tokenValues.forEach { tokenValue ->
            writeUInt16(tokenValue.data.size)
            tokenValue.data.copyInto(encoded, destinationOffset = offset)
            offset += tokenValue.data.size
        }
        writeUInt16(payload.size)
        payload.copyInto(encoded, destinationOffset = offset)

        return encoded
    }

    companion object {
        val MAX_ENCODED_SIZE: Int = UShort.MAX_VALUE.toInt()
        private val MAX_SEGMENT_COUNT: Int = UShort.MAX_VALUE.toInt()
        private val MAX_SEGMENT_LENGTH: Int = UShort.MAX_VALUE.toInt()

        fun decode(
            direction: MessageDirection,
            expectedTokens: List<HandshakeToken>,
            encoded: ByteArray
        ): HandshakeMessage {
            require(encoded.size <= MAX_ENCODED_SIZE) {
                "Handshake message exceeds the Noise maximum message size of $MAX_ENCODED_SIZE bytes."
            }

            var offset = 0
            fun readUInt16(): Int {
                require(offset + 2 <= encoded.size) { "Truncated uint16." }
                val value = ((encoded[offset].toInt() and 0xFF) shl 8) or
                    (encoded[offset + 1].toInt() and 0xFF)
                offset += 2
                return value
            }

            fun readBytes(length: Int): ByteArray {
                require(offset + length <= encoded.size) { "Truncated byte segment." }
                return encoded.copyOfRange(offset, offset + length).also { offset += length }
            }

            val tokenPayloadCount = readUInt16()
            require(tokenPayloadCount == expectedTokens.size) {
                "Unexpected token payload count. Expected ${expectedTokens.size} but received $tokenPayloadCount."
            }
            val tokenValues = ArrayList<HandshakeTokenValue>(tokenPayloadCount)
            expectedTokens.forEach { token ->
                val tokenPayload = readBytes(readUInt16())
                tokenValues += HandshakeTokenValue(token = token, data = tokenPayload)
            }
            val payload = readBytes(readUInt16())
            require(offset == encoded.size) { "Unexpected trailing bytes." }

            return HandshakeMessage(
                direction = direction,
                tokenValues = tokenValues,
                payload = payload
            )
        }
    }
}

class HandshakeState private constructor(
    val pattern: HandshakePattern,
    val role: HandshakeRole,
    private val symmetricState: SymmetricState,
    private val diffieHellmanFunction: NoiseDiffieHellmanFunction,
    private val ephemeralKeyGenerator: () -> NoiseKeyPair,
    localStatic: NoiseKeyPair?,
    localEphemeral: NoiseKeyPair?,
    remoteStatic: ByteArray?,
    remoteEphemeral: ByteArray?
) {
    private var localStaticKey: NoiseKeyPair? = localStatic?.copyKeyPair()
    private var localEphemeralKey: NoiseKeyPair? = localEphemeral?.copyKeyPair()
    private var remoteStaticKey: ByteArray? = remoteStatic?.copyOf()
    private var remoteEphemeralKey: ByteArray? = remoteEphemeral?.copyOf()
    private var messageIndex: Int = 0

    init {
        mixPreMessages()
    }

    fun expectedDirection(): MessageDirection? = pattern.messages.getOrNull(messageIndex)?.direction

    fun isComplete(): Boolean = messageIndex >= pattern.messages.size

    fun handshakeHash(): ByteArray = symmetricState.handshakeHash

    fun writeMessage(payload: ByteArray = EMPTY_BYTE_ARRAY): HandshakeMessage {
        val messagePattern = nextMessagePattern()
        check(messagePattern.direction.isSentBy(role)) { "Expected to read before writing next message." }

        val tokenValues = mutableListOf<HandshakeTokenValue>()
        for (token in messagePattern.tokens) {
            when (token) {
                HandshakeToken.E -> {
                    val generated = ephemeralKeyGenerator().copyKeyPair()
                    localEphemeralKey = generated
                    tokenValues += HandshakeTokenValue(token = token, data = generated.publicKey.copyOf())
                    symmetricState.mixHash(generated.publicKey)
                }

                HandshakeToken.S -> {
                    val staticPublicKey = requireLocalStatic().publicKey
                    val encodedStatic = if (symmetricState.hasCipherKey()) {
                        symmetricState.encryptAndHash(staticPublicKey)
                    } else {
                        symmetricState.mixHash(staticPublicKey)
                        staticPublicKey.copyOf()
                    }
                    tokenValues += HandshakeTokenValue(token = token, data = encodedStatic)
                }

                HandshakeToken.EE,
                HandshakeToken.ES,
                HandshakeToken.SE,
                HandshakeToken.SS -> symmetricState.mixKey(performDh(token))
            }
        }

        val encryptedPayload = symmetricState.encryptAndHash(payload)
        messageIndex += 1

        return HandshakeMessage(
            direction = messagePattern.direction,
            tokenValues = tokenValues,
            payload = encryptedPayload
        ).also(HandshakeMessage::encodedSize)
    }

    fun readMessage(message: HandshakeMessage): ByteArray {
        message.encodedSize()
        val messagePattern = nextMessagePattern()
        check(!messagePattern.direction.isSentBy(role)) { "Expected to write before reading next message." }
        require(message.direction == messagePattern.direction) { "Unexpected message direction." }

        val tokenIterator = message.tokenValues.iterator()
        for (token in messagePattern.tokens) {
            when (token) {
                HandshakeToken.E -> {
                    val tokenValue = readTokenValue(tokenIterator, token)
                    remoteEphemeralKey = tokenValue.data.copyOf()
                    symmetricState.mixHash(tokenValue.data)
                }

                HandshakeToken.S -> {
                    val tokenValue = readTokenValue(tokenIterator, token)
                    val remoteStatic = if (symmetricState.hasCipherKey()) {
                        symmetricState.decryptAndHash(tokenValue.data)
                    } else {
                        symmetricState.mixHash(tokenValue.data)
                        tokenValue.data.copyOf()
                    }
                    remoteStaticKey = remoteStatic
                }

                HandshakeToken.EE,
                HandshakeToken.ES,
                HandshakeToken.SE,
                HandshakeToken.SS -> symmetricState.mixKey(performDh(token))
            }
        }

        require(!tokenIterator.hasNext()) { "Unexpected token data for current message pattern." }

        val plaintext = symmetricState.decryptAndHash(message.payload)
        messageIndex += 1
        return plaintext
    }

    fun splitTransportStates(): Pair<CipherState, CipherState> {
        check(isComplete()) { "Handshake is not complete." }

        val (initiatorToResponder, responderToInitiator) = symmetricState.split()
        return if (role == HandshakeRole.INITIATOR) {
            initiatorToResponder to responderToInitiator
        } else {
            responderToInitiator to initiatorToResponder
        }
    }

    private fun mixPreMessages() {
        for (preMessage in pattern.preMessages) {
            for (token in preMessage.tokens) {
                val keyMaterial = resolvePreMessageKey(preMessage.direction, token)
                symmetricState.mixHash(keyMaterial)
            }
        }
    }

    private fun resolvePreMessageKey(direction: MessageDirection, token: HandshakeToken): ByteArray {
        val isLocalSender = direction.isSentBy(role)
        return when (token) {
            HandshakeToken.E -> {
                if (isLocalSender) {
                    requireLocalEphemeral().publicKey.copyOf()
                } else {
                    requireRemoteEphemeral().copyOf()
                }
            }

            HandshakeToken.S -> {
                if (isLocalSender) {
                    requireLocalStatic().publicKey.copyOf()
                } else {
                    requireRemoteStatic().copyOf()
                }
            }

            else -> error("Unsupported pre-message token: $token")
        }
    }

    private fun nextMessagePattern(): MessagePattern {
        return pattern.messages.getOrNull(messageIndex)
            ?: error("Handshake already complete.")
    }

    private fun readTokenValue(
        iterator: Iterator<HandshakeTokenValue>,
        expectedToken: HandshakeToken
    ): HandshakeTokenValue {
        require(iterator.hasNext()) { "Missing token data for $expectedToken." }
        val tokenValue = iterator.next()
        require(tokenValue.token == expectedToken) {
            "Unexpected token order. Expected $expectedToken but received ${tokenValue.token}."
        }
        return tokenValue
    }

    private fun performDh(token: HandshakeToken): ByteArray {
        return when (token) {
            HandshakeToken.EE -> diffieHellmanFunction.dh(
                localPrivateKey = requireLocalEphemeral().privateKey,
                remotePublicKey = requireRemoteEphemeral()
            )

            HandshakeToken.ES -> {
                if (role == HandshakeRole.INITIATOR) {
                    diffieHellmanFunction.dh(
                        localPrivateKey = requireLocalEphemeral().privateKey,
                        remotePublicKey = requireRemoteStatic()
                    )
                } else {
                    diffieHellmanFunction.dh(
                        localPrivateKey = requireLocalStatic().privateKey,
                        remotePublicKey = requireRemoteEphemeral()
                    )
                }
            }

            HandshakeToken.SE -> {
                if (role == HandshakeRole.INITIATOR) {
                    diffieHellmanFunction.dh(
                        localPrivateKey = requireLocalStatic().privateKey,
                        remotePublicKey = requireRemoteEphemeral()
                    )
                } else {
                    diffieHellmanFunction.dh(
                        localPrivateKey = requireLocalEphemeral().privateKey,
                        remotePublicKey = requireRemoteStatic()
                    )
                }
            }

            HandshakeToken.SS -> diffieHellmanFunction.dh(
                localPrivateKey = requireLocalStatic().privateKey,
                remotePublicKey = requireRemoteStatic()
            )

            else -> error("Token $token does not represent a DH operation.")
        }
    }

    private fun requireLocalStatic(): NoiseKeyPair {
        return localStaticKey ?: error("Local static key is required by the handshake pattern.")
    }

    private fun requireLocalEphemeral(): NoiseKeyPair {
        return localEphemeralKey ?: error("Local ephemeral key is required by the handshake state.")
    }

    private fun requireRemoteStatic(): ByteArray {
        return remoteStaticKey ?: error("Remote static key is required by the handshake pattern.")
    }

    private fun requireRemoteEphemeral(): ByteArray {
        return remoteEphemeralKey ?: error("Remote ephemeral key is required by the handshake state.")
    }

    companion object {
        private val EMPTY_BYTE_ARRAY = ByteArray(0)

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
        ): HandshakeState {
            val symmetricState = SymmetricState(
                hashFunction = cryptoSuite.hash,
                keyDerivationFunction = cryptoSuite.keyDerivation,
                cipherFunction = cryptoSuite.cipher,
                protocolName = protocolName
            )
            symmetricState.mixHash(prologue)

            return HandshakeState(
                pattern = pattern,
                role = role,
                symmetricState = symmetricState,
                diffieHellmanFunction = cryptoSuite.diffieHellman,
                ephemeralKeyGenerator = ephemeralKeyGenerator,
                localStatic = localStatic,
                localEphemeral = localEphemeral,
                remoteStatic = remoteStatic,
                remoteEphemeral = remoteEphemeral
            )
        }
    }
}

private fun NoiseKeyPair.copyKeyPair(): NoiseKeyPair = NoiseKeyPair(
    privateKey = privateKey.copyOf(),
    publicKey = publicKey.copyOf()
)
