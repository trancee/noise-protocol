package dev.noiseprotocol.core

data class HandshakeTokenValue(
    val token: HandshakeToken,
    val data: ByteArray
)

data class HandshakeMessage(
    val direction: MessageDirection,
    val tokenValues: List<HandshakeTokenValue>,
    val payload: ByteArray
)

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
        )
    }

    fun readMessage(message: HandshakeMessage): ByteArray {
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
