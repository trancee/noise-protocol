package com.noise.protocol.pattern

/** Token types in a Noise handshake message pattern. */
enum class Token {
    E, S, EE, ES, SE, SS, PSK
}

/** A message pattern is a sequence of tokens processed in one direction. */
typealias MessagePattern = List<Token>

/**
 * Defines a Noise handshake pattern with pre-messages and message patterns.
 */
data class HandshakePattern(
    val name: String,
    val initiatorPreMessage: List<Token> = emptyList(),
    val responderPreMessage: List<Token> = emptyList(),
    val messagePatterns: List<MessagePattern>
) {
    /** Apply PSK modifiers. Position 0 = start of first message, N = end of Nth message. */
    fun withPSK(positions: List<Int>): HandshakePattern {
        val modified = messagePatterns.map { it.toMutableList() }
        for (pos in positions.sorted()) {
            if (pos == 0) {
                modified[0].add(0, Token.PSK)
            } else {
                val msgIndex = pos - 1
                if (msgIndex < modified.size) {
                    modified[msgIndex].add(Token.PSK)
                }
            }
        }
        val pskSuffix = positions.joinToString("+") { "psk$it" }
        return copy(
            name = "$name$pskSuffix",
            messagePatterns = modified
        )
    }

    companion object {
        // One-way patterns
        val N = HandshakePattern("N", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES)))
        val K = HandshakePattern("K", initiatorPreMessage = listOf(Token.S),
            responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES, Token.SS)))
        val X = HandshakePattern("X", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES, Token.S, Token.SS)))

        // Fundamental interactive patterns
        val NN = HandshakePattern("NN", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE)))
        val NK = HandshakePattern("NK", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES), listOf(Token.E, Token.EE)))
        val NX = HandshakePattern("NX", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE, Token.S, Token.ES)))
        val XN = HandshakePattern("XN", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE), listOf(Token.S, Token.SE)))
        val XK = HandshakePattern("XK", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES), listOf(Token.E, Token.EE),
                listOf(Token.S, Token.SE)))
        val XX = HandshakePattern("XX", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE, Token.S, Token.ES),
            listOf(Token.S, Token.SE)))
        val KN = HandshakePattern("KN", initiatorPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E), listOf(Token.E, Token.EE, Token.SE)))
        val KK = HandshakePattern("KK", initiatorPreMessage = listOf(Token.S),
            responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES, Token.SS),
                listOf(Token.E, Token.EE, Token.SE)))
        val KX = HandshakePattern("KX", initiatorPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E),
                listOf(Token.E, Token.EE, Token.SE, Token.S, Token.ES)))
        val IN = HandshakePattern("IN", messagePatterns = listOf(
            listOf(Token.E, Token.S), listOf(Token.E, Token.EE, Token.SE)))
        val IK = HandshakePattern("IK", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES, Token.S, Token.SS),
                listOf(Token.E, Token.EE, Token.SE)))
        val IX = HandshakePattern("IX", messagePatterns = listOf(
            listOf(Token.E, Token.S),
            listOf(Token.E, Token.EE, Token.SE, Token.S, Token.ES)))

        // Deferred patterns
        val NK1 = HandshakePattern("NK1", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E), listOf(Token.E, Token.EE, Token.ES)))
        val NX1 = HandshakePattern("NX1", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE, Token.S), listOf(Token.ES)))
        val X1N = HandshakePattern("X1N", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE), listOf(Token.S), listOf(Token.SE)))
        val X1K = HandshakePattern("X1K", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES), listOf(Token.E, Token.EE),
                listOf(Token.S), listOf(Token.SE)))
        val XK1 = HandshakePattern("XK1", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E), listOf(Token.E, Token.EE, Token.ES),
                listOf(Token.S, Token.SE)))
        val X1K1 = HandshakePattern("X1K1", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E), listOf(Token.E, Token.EE, Token.ES),
                listOf(Token.S), listOf(Token.SE)))
        val X1X = HandshakePattern("X1X", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE, Token.S, Token.ES),
            listOf(Token.S), listOf(Token.SE)))
        val XX1 = HandshakePattern("XX1", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE, Token.S),
            listOf(Token.ES, Token.S, Token.SE)))
        val X1X1 = HandshakePattern("X1X1", messagePatterns = listOf(
            listOf(Token.E), listOf(Token.E, Token.EE, Token.S),
            listOf(Token.ES, Token.S), listOf(Token.SE)))
        val K1N = HandshakePattern("K1N", initiatorPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E), listOf(Token.E, Token.EE), listOf(Token.SE)))
        val K1K = HandshakePattern("K1K", initiatorPreMessage = listOf(Token.S),
            responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES), listOf(Token.E, Token.EE),
                listOf(Token.SE)))
        val KK1 = HandshakePattern("KK1", initiatorPreMessage = listOf(Token.S),
            responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E), listOf(Token.E, Token.EE, Token.SE, Token.ES)))
        val K1K1 = HandshakePattern("K1K1", initiatorPreMessage = listOf(Token.S),
            responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E), listOf(Token.E, Token.EE, Token.ES),
                listOf(Token.SE)))
        val K1X = HandshakePattern("K1X", initiatorPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E),
                listOf(Token.E, Token.EE, Token.S, Token.ES), listOf(Token.SE)))
        val KX1 = HandshakePattern("KX1", initiatorPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E),
                listOf(Token.E, Token.EE, Token.SE, Token.S), listOf(Token.ES)))
        val K1X1 = HandshakePattern("K1X1", initiatorPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E), listOf(Token.E, Token.EE, Token.S),
                listOf(Token.SE, Token.ES)))
        val I1N = HandshakePattern("I1N", messagePatterns = listOf(
            listOf(Token.E, Token.S), listOf(Token.E, Token.EE), listOf(Token.SE)))
        val I1K = HandshakePattern("I1K", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.ES, Token.S),
                listOf(Token.E, Token.EE), listOf(Token.SE)))
        val IK1 = HandshakePattern("IK1", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.S),
                listOf(Token.E, Token.EE, Token.SE, Token.ES)))
        val I1K1 = HandshakePattern("I1K1", responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(listOf(Token.E, Token.S),
                listOf(Token.E, Token.EE, Token.ES), listOf(Token.SE)))
        val I1X = HandshakePattern("I1X", messagePatterns = listOf(
            listOf(Token.E, Token.S), listOf(Token.E, Token.EE, Token.S, Token.ES),
            listOf(Token.SE)))
        val IX1 = HandshakePattern("IX1", messagePatterns = listOf(
            listOf(Token.E, Token.S), listOf(Token.E, Token.EE, Token.SE, Token.S),
            listOf(Token.ES)))
        val I1X1 = HandshakePattern("I1X1", messagePatterns = listOf(
            listOf(Token.E, Token.S), listOf(Token.E, Token.EE, Token.S),
            listOf(Token.SE, Token.ES)))

        // Fallback - roles reversed from original XX, es/se swapped
        val XXfallback = HandshakePattern("XXfallback",
            responderPreMessage = listOf(Token.E),
            messagePatterns = listOf(
                listOf(Token.E, Token.EE, Token.S, Token.SE),
                listOf(Token.S, Token.ES)))

        // Named PSK patterns
        val NKpsk0 = HandshakePattern("NKpsk0",
            responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(
                listOf(Token.PSK, Token.E, Token.ES),
                listOf(Token.E, Token.EE)))
        val IKpsk2 = HandshakePattern("IKpsk2",
            responderPreMessage = listOf(Token.S),
            messagePatterns = listOf(
                listOf(Token.E, Token.ES, Token.S, Token.SS),
                listOf(Token.E, Token.EE, Token.SE, Token.PSK)))

        /** All named patterns. */
        val all: Map<String, HandshakePattern> = mapOf(
            "N" to N, "K" to K, "X" to X,
            "NN" to NN, "NK" to NK, "NX" to NX,
            "XN" to XN, "XK" to XK, "XX" to XX,
            "KN" to KN, "KK" to KK, "KX" to KX,
            "IN" to IN, "IK" to IK, "IX" to IX,
            "NK1" to NK1, "NX1" to NX1,
            "X1N" to X1N, "X1K" to X1K, "XK1" to XK1, "X1K1" to X1K1,
            "X1X" to X1X, "XX1" to XX1, "X1X1" to X1X1,
            "K1N" to K1N, "K1K" to K1K, "KK1" to KK1, "K1K1" to K1K1,
            "K1X" to K1X, "KX1" to KX1, "K1X1" to K1X1,
            "I1N" to I1N, "I1K" to I1K, "IK1" to IK1, "I1K1" to I1K1,
            "I1X" to I1X, "IX1" to IX1, "I1X1" to I1X1,
            "XXfallback" to XXfallback,
            "NKpsk0" to NKpsk0,
            "IKpsk2" to IKpsk2
        )

        fun named(name: String): HandshakePattern =
            all[name] ?: throw com.noise.protocol.NoiseException.UnknownPattern(name)
    }
}
