package com.noise.protocol

import com.noise.protocol.crypto.CipherSuite
import com.noise.protocol.crypto.NoiseKeyPair
import com.noise.protocol.pattern.HandshakePattern
import com.noise.protocol.pattern.Token
import com.noise.protocol.state.HandshakeState
import org.junit.jupiter.api.Test
import kotlin.system.measureNanoTime

class BenchmarkTests {

    private val allSuites = listOf(
        CipherSuite.NOISE_25519_CHACHAPOLY_SHA256,
        CipherSuite.NOISE_25519_CHACHAPOLY_SHA512,
        CipherSuite.NOISE_25519_CHACHAPOLY_BLAKE2S,
        CipherSuite.NOISE_25519_CHACHAPOLY_BLAKE2B,
        CipherSuite.NOISE_25519_AESGCM_SHA256,
        CipherSuite.NOISE_25519_AESGCM_SHA512,
        CipherSuite.NOISE_25519_AESGCM_BLAKE2S,
        CipherSuite.NOISE_25519_AESGCM_BLAKE2B,
    )

    private fun suiteName(suite: CipherSuite): String =
        "${suite.cipherName}_${suite.hashName}"

    private data class KeyRequirements(
        val initiatorNeedsS: Boolean,
        val responderNeedsS: Boolean,
        val initiatorNeedsRS: Boolean,
        val responderNeedsRS: Boolean,
        val needsPsk: Boolean,
    )

    private fun keyRequirements(pattern: HandshakePattern): KeyRequirements {
        val initSendsS = pattern.initiatorPreMessage.contains(Token.S) ||
            pattern.messagePatterns.filterIndexed { i, _ -> i % 2 == 0 }.any { it.contains(Token.S) }
        val respSendsS = pattern.responderPreMessage.contains(Token.S) ||
            pattern.messagePatterns.filterIndexed { i, _ -> i % 2 == 1 }.any { it.contains(Token.S) }
        val initNeedsRS = pattern.responderPreMessage.contains(Token.S)
        val respNeedsRS = pattern.initiatorPreMessage.contains(Token.S)
        val needsPsk = pattern.name.contains("psk", ignoreCase = true)
        return KeyRequirements(initSendsS, respSendsS, initNeedsRS, respNeedsRS, needsPsk)
    }

    private fun createHandshakePair(
        pattern: HandshakePattern,
        suite: CipherSuite,
    ): Pair<HandshakeState, HandshakeState> {
        val reqs = keyRequirements(pattern)

        val initStatic = if (reqs.initiatorNeedsS) NoiseKeyPair.generate() else null
        val respStatic = if (reqs.responderNeedsS) NoiseKeyPair.generate() else null

        val initRS = if (reqs.initiatorNeedsRS) respStatic?.publicKey else null
        val respRS = if (reqs.responderNeedsRS) initStatic?.publicKey else null

        val psks = if (reqs.needsPsk) {
            val pskCount = pattern.messagePatterns.sumOf { mp -> mp.count { it == Token.PSK } }
            List(pskCount) { ByteArray(32) }
        } else {
            emptyList()
        }

        val initiator = HandshakeState(
            pattern = pattern,
            initiator = true,
            suite = suite,
            s = initStatic,
            rs = initRS,
            psks = psks,
        )
        val responder = HandshakeState(
            pattern = pattern,
            initiator = false,
            suite = suite,
            s = respStatic,
            rs = respRS,
            psks = psks,
        )
        return initiator to responder
    }

    private fun runHandshake(initiator: HandshakeState, responder: HandshakeState, messageCount: Int) {
        var sender = initiator
        var receiver = responder
        for (i in 0 until messageCount) {
            val (msg, _) = sender.writeMessage()
            receiver.readMessage(msg)
            val temp = sender
            sender = receiver
            receiver = temp
        }
    }

    // --- Handshake Benchmark ---

    @Test
    fun testHandshakeBenchmark() {
        val warmupIterations = 5
        val measuredIterations = 20

        val patterns = HandshakePattern.all.filter { it.key != "XXfallback" }

        println()
        println("=== Handshake Benchmark ($measuredIterations iterations, $warmupIterations warmup) ===")
        println(
            "%-34s %-15s %-10s %10s %10s %10s".format(
                "Suite", "Pattern", "Messages", "Avg (µs)", "Min (µs)", "Max (µs)"
            )
        )

        for (suite in allSuites) {
            for ((name, pattern) in patterns) {
                val messageCount = pattern.messagePatterns.size

                // Warmup
                repeat(warmupIterations) {
                    val (init, resp) = createHandshakePair(pattern, suite)
                    runHandshake(init, resp, messageCount)
                }

                // Measured
                val timings = LongArray(measuredIterations)
                repeat(measuredIterations) { idx ->
                    val (init, resp) = createHandshakePair(pattern, suite)
                    timings[idx] = measureNanoTime {
                        runHandshake(init, resp, messageCount)
                    }
                }

                val avgUs = timings.average() / 1000.0
                val minUs = timings.min() / 1000.0
                val maxUs = timings.max() / 1000.0

                println(
                    "%-34s %-15s %-10d %10.1f %10.1f %10.1f".format(
                        suiteName(suite), name, messageCount, avgUs, minUs, maxUs
                    )
                )
            }
        }
    }

    // --- Transport Benchmark ---

    @Test
    fun testTransportBenchmark() {
        val warmupIterations = 100
        val measuredIterations = 1000
        val payloadSize = 1024
        val payload = ByteArray(payloadSize) { (it % 256).toByte() }
        val emptyAd = ByteArray(0)

        println()
        println("=== Transport Benchmark ($measuredIterations iterations, $warmupIterations warmup) ===")
        println(
            "%-34s %14s %14s %18s".format(
                "Suite", "Encrypt (µs)", "Decrypt (µs)", "Throughput (MB/s)"
            )
        )

        for (suite in allSuites) {
            val pattern = HandshakePattern.NN
            val (init, resp) = createHandshakePair(pattern, suite)

            val (msg1, _) = init.writeMessage()
            val (_, _) = resp.readMessage(msg1)
            val (msg2, initTransport) = resp.writeMessage()
            val (_, respTransport) = init.readMessage(msg2)

            val sendCipher = initTransport!!.sendCipher
            val recvCipher = respTransport!!.receiveCipher

            // Warmup
            repeat(warmupIterations) {
                val ct = sendCipher.encryptWithAd(emptyAd, payload)
                recvCipher.decryptWithAd(emptyAd, ct)
            }

            // Measured
            val encryptTimings = LongArray(measuredIterations)
            val decryptTimings = LongArray(measuredIterations)

            repeat(measuredIterations) { idx ->
                var ct: ByteArray
                encryptTimings[idx] = measureNanoTime {
                    ct = sendCipher.encryptWithAd(emptyAd, payload)
                }
                decryptTimings[idx] = measureNanoTime {
                    recvCipher.decryptWithAd(emptyAd, ct)
                }
            }

            val avgEncryptUs = encryptTimings.average() / 1000.0
            val avgDecryptUs = decryptTimings.average() / 1000.0
            val totalSeconds = (encryptTimings.sum() + decryptTimings.sum()) / 1_000_000_000.0
            val totalBytes = measuredIterations.toLong() * payloadSize
            val throughputMBs = (totalBytes / totalSeconds) / (1024.0 * 1024.0)

            println(
                "%-34s %14.1f %14.1f %18.1f".format(
                    suiteName(suite), avgEncryptUs, avgDecryptUs, throughputMBs
                )
            )
        }
    }

    // --- XXfallback Benchmark ---

    @Test
    fun testXXfallbackBenchmark() {
        val warmupIterations = 5
        val measuredIterations = 20

        println()
        println("=== XXfallback Benchmark ($measuredIterations iterations, $warmupIterations warmup) ===")
        println(
            "%-34s %10s %10s %10s".format(
                "Suite", "Avg (µs)", "Min (µs)", "Max (µs)"
            )
        )

        for (suite in allSuites) {
            // Warmup
            repeat(warmupIterations) {
                runXXfallbackHandshake(suite)
            }

            // Measured
            val timings = LongArray(measuredIterations)
            repeat(measuredIterations) { idx ->
                timings[idx] = measureNanoTime {
                    runXXfallbackHandshake(suite)
                }
            }

            val avgUs = timings.average() / 1000.0
            val minUs = timings.min() / 1000.0
            val maxUs = timings.max() / 1000.0

            println(
                "%-34s %10.1f %10.1f %10.1f".format(
                    suiteName(suite), avgUs, minUs, maxUs
                )
            )
        }
    }

    private fun runXXfallbackHandshake(suite: CipherSuite) {
        val respStatic = NoiseKeyPair.generate()
        val initStatic = NoiseKeyPair.generate()
        val initEphemeral = NoiseKeyPair.generate()

        // Fallback initiator = original responder: knows its own static key and the
        // initiator's ephemeral public key (extracted from the failed IK msg1).
        val fallbackInitiator = HandshakeState(
            pattern = HandshakePattern.XXfallback,
            initiator = true,
            suite = suite,
            s = respStatic,
            re = initEphemeral.publicKey,
        )

        // Fallback responder = original initiator: uses its own static key and
        // the ephemeral key pair it generated in the original IK attempt.
        val fallbackResponder = HandshakeState(
            pattern = HandshakePattern.XXfallback,
            initiator = false,
            suite = suite,
            s = initStatic,
            e = initEphemeral,
        )

        // XXfallback has 2 message patterns
        runHandshake(fallbackInitiator, fallbackResponder, messageCount = 2)
    }
}
