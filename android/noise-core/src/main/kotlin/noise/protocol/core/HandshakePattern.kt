package noise.protocol.core

enum class HandshakeRole {
    INITIATOR,
    RESPONDER
}

enum class MessageDirection {
    INITIATOR_TO_RESPONDER,
    RESPONDER_TO_INITIATOR;

    fun isSentBy(role: HandshakeRole): Boolean {
        return when (this) {
            INITIATOR_TO_RESPONDER -> role == HandshakeRole.INITIATOR
            RESPONDER_TO_INITIATOR -> role == HandshakeRole.RESPONDER
        }
    }
}

enum class HandshakeToken {
    E,
    S,
    EE,
    ES,
    SE,
    SS
}

data class PreMessagePattern(
    val direction: MessageDirection,
    val tokens: List<HandshakeToken>
)

data class MessagePattern(
    val direction: MessageDirection,
    val tokens: List<HandshakeToken>
)

enum class HandshakePattern(
    val protocolName: String,
    val preMessages: List<PreMessagePattern>,
    val messages: List<MessagePattern>
) {
    NN(
        protocolName = "Noise_NN",
        preMessages = emptyList(),
        messages = listOf(
            message(MessageDirection.INITIATOR_TO_RESPONDER, HandshakeToken.E),
            message(MessageDirection.RESPONDER_TO_INITIATOR, HandshakeToken.E, HandshakeToken.EE)
        )
    ),
    NK(
        protocolName = "Noise_NK",
        preMessages = listOf(
            preMessage(MessageDirection.RESPONDER_TO_INITIATOR, HandshakeToken.S)
        ),
        messages = listOf(
            message(MessageDirection.INITIATOR_TO_RESPONDER, HandshakeToken.E, HandshakeToken.ES),
            message(MessageDirection.RESPONDER_TO_INITIATOR, HandshakeToken.E, HandshakeToken.EE)
        )
    ),
    KK(
        protocolName = "Noise_KK",
        preMessages = listOf(
            preMessage(MessageDirection.INITIATOR_TO_RESPONDER, HandshakeToken.S),
            preMessage(MessageDirection.RESPONDER_TO_INITIATOR, HandshakeToken.S)
        ),
        messages = listOf(
            message(MessageDirection.INITIATOR_TO_RESPONDER, HandshakeToken.E, HandshakeToken.ES, HandshakeToken.SS),
            message(MessageDirection.RESPONDER_TO_INITIATOR, HandshakeToken.E, HandshakeToken.EE, HandshakeToken.SE)
        )
    ),
    IK(
        protocolName = "Noise_IK",
        preMessages = listOf(
            preMessage(MessageDirection.RESPONDER_TO_INITIATOR, HandshakeToken.S)
        ),
        messages = listOf(
            message(
                MessageDirection.INITIATOR_TO_RESPONDER,
                HandshakeToken.E,
                HandshakeToken.ES,
                HandshakeToken.S,
                HandshakeToken.SS
            ),
            message(MessageDirection.RESPONDER_TO_INITIATOR, HandshakeToken.E, HandshakeToken.EE, HandshakeToken.SE)
        )
    ),
    XX(
        protocolName = "Noise_XX",
        preMessages = emptyList(),
        messages = listOf(
            message(MessageDirection.INITIATOR_TO_RESPONDER, HandshakeToken.E),
            message(
                MessageDirection.RESPONDER_TO_INITIATOR,
                HandshakeToken.E,
                HandshakeToken.EE,
                HandshakeToken.S,
                HandshakeToken.ES
            ),
            message(MessageDirection.INITIATOR_TO_RESPONDER, HandshakeToken.S, HandshakeToken.SE)
        )
    )
}

private fun preMessage(direction: MessageDirection, vararg tokens: HandshakeToken): PreMessagePattern {
    return PreMessagePattern(direction = direction, tokens = tokens.toList())
}

private fun message(direction: MessageDirection, vararg tokens: HandshakeToken): MessagePattern {
    return MessagePattern(direction = direction, tokens = tokens.toList())
}
