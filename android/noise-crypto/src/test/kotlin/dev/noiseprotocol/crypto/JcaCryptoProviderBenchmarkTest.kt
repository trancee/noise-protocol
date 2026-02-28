package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.HandshakePattern
import dev.noiseprotocol.core.HandshakeRole
import dev.noiseprotocol.core.HandshakeState
import dev.noiseprotocol.core.MessageDirection
import dev.noiseprotocol.core.NoiseCryptoSuite
import dev.noiseprotocol.core.NoiseDiffieHellmanFunction
import dev.noiseprotocol.core.NoiseKeyPair
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("benchmark")
class JcaCryptoProviderBenchmarkTest {
    private val provider = JcaCryptoProvider()

    @Test
    fun measuresHandshakeAcrossPatternsForSupportedAeadSuites() {
        val patterns = listOf(
            HandshakePattern.NN,
            HandshakePattern.NK,
            HandshakePattern.KK,
            HandshakePattern.IK,
            HandshakePattern.XX
        )
        val variations = listOf(
            NoiseCryptoAlgorithms(
                dh = NoiseDhAlgorithm.X25519,
                aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
                hash = NoiseHashAlgorithm.SHA256
            ),
            NoiseCryptoAlgorithms(
                dh = NoiseDhAlgorithm.X25519,
                aead = NoiseAeadAlgorithm.AES_GCM,
                hash = NoiseHashAlgorithm.SHA256
            )
        )
        val measuredRounds = 20

        variations.forEach { algorithms ->
            val suite = provider.createSuite(algorithms)
            patterns.forEach { pattern ->
                val warmupFixture = HandshakeFixture.generate(suite.diffieHellman, rounds = 3)
                runHandshakeRounds(
                    suite = suite,
                    pattern = pattern,
                    algorithms = algorithms,
                    rounds = 3,
                    fixture = warmupFixture
                )

                val fixture = HandshakeFixture.generate(suite.diffieHellman, rounds = measuredRounds)
                val startNs = System.nanoTime()
                val checksum = runHandshakeRounds(
                    suite = suite,
                    pattern = pattern,
                    algorithms = algorithms,
                    rounds = measuredRounds,
                    fixture = fixture
                )
                val elapsedNs = System.nanoTime() - startNs
                val nsPerOp = elapsedNs / measuredRounds
                val opsPerSec = measuredRounds * 1_000_000_000.0 / elapsedNs.toDouble()

                assertTrue(elapsedNs > 0L)
                assertTrue(checksum > 0L)
                println(
                    "benchmark noise-crypto handshake pattern=${pattern.name.lowercase()} " +
                        "dh=${algorithms.dh.name.lowercase()} aead=${algorithms.aead.name.lowercase()} " +
                        "hash=${algorithms.hash.name.lowercase()} rounds=$measuredRounds " +
                        "elapsed_ns=$elapsedNs ns_per_op=$nsPerOp ops_per_s=$opsPerSec checksum=$checksum"
                )
            }
        }
    }

    @Test
    fun measuresHashAndHkdfAcrossSupportedAlgorithms() {
        val hashes = listOf(NoiseHashAlgorithm.SHA256, NoiseHashAlgorithm.SHA512)
        val measuredIterations = 8_000

        hashes.forEach { hash ->
            val suite = provider.createSuite(
                NoiseCryptoAlgorithms(
                    dh = NoiseDhAlgorithm.X25519,
                    aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
                    hash = hash
                )
            )
            val expectedLength = if (hash == NoiseHashAlgorithm.SHA256) 32 else 64
            runHashAndHkdfLoops(suite, iterations = 500, expectedHashLength = expectedLength)

            val startNs = System.nanoTime()
            val checksum = runHashAndHkdfLoops(
                suite = suite,
                iterations = measuredIterations,
                expectedHashLength = expectedLength
            )
            val elapsedNs = System.nanoTime() - startNs
            val nsPerOp = elapsedNs / measuredIterations
            val opsPerSec = measuredIterations * 1_000_000_000.0 / elapsedNs.toDouble()

            assertTrue(elapsedNs > 0L)
            assertTrue(checksum > 0L)
            println(
                "benchmark noise-crypto hash_hkdf hash=${hash.name.lowercase()} iterations=$measuredIterations " +
                    "elapsed_ns=$elapsedNs ns_per_op=$nsPerOp ops_per_s=$opsPerSec checksum=$checksum"
            )
        }
    }

    @Test
    fun measuresX25519DiffieHellmanThroughput() {
        val suite = provider.createSuite(
            NoiseCryptoAlgorithms(
                dh = NoiseDhAlgorithm.X25519,
                aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
                hash = NoiseHashAlgorithm.SHA256
            )
        )
        val measuredIterations = 2_000
        val warmupKeys = List(41) { suite.diffieHellman.generateKeyPair() }
        runDhLoops(
            diffieHellman = suite.diffieHellman,
            keyPairs = warmupKeys,
            iterations = 40
        )

        val keyPairs = List(measuredIterations + 1) { suite.diffieHellman.generateKeyPair() }
        val startNs = System.nanoTime()
        val checksum = runDhLoops(
            diffieHellman = suite.diffieHellman,
            keyPairs = keyPairs,
            iterations = measuredIterations
        )
        val elapsedNs = System.nanoTime() - startNs
        val nsPerOp = elapsedNs / measuredIterations
        val opsPerSec = measuredIterations * 1_000_000_000.0 / elapsedNs.toDouble()

        assertTrue(elapsedNs > 0L)
        assertTrue(checksum > 0L)
        println(
            "benchmark noise-crypto dh dh=x25519 iterations=$measuredIterations " +
                "elapsed_ns=$elapsedNs ns_per_op=$nsPerOp ops_per_s=$opsPerSec checksum=$checksum"
        )
    }

    @Test
    fun reportsUnsupportedProviderAlgorithms() {
        val unsupportedDhStartNs = System.nanoTime()
        val unsupportedDhError = assertThrows(UnsupportedOperationException::class.java) {
            provider.createSuite(
                NoiseCryptoAlgorithms(
                    dh = NoiseDhAlgorithm.X448,
                    aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
                    hash = NoiseHashAlgorithm.SHA256
                )
            )
        }
        val unsupportedDhElapsedNs = System.nanoTime() - unsupportedDhStartNs
        assertTrue(unsupportedDhError.message.orEmpty().contains("X448"))
        println(
            "benchmark noise-crypto unsupported dh=x448 elapsed_ns=$unsupportedDhElapsedNs " +
                "message=${unsupportedDhError.message.orEmpty()}"
        )

        listOf(NoiseHashAlgorithm.BLAKE2S, NoiseHashAlgorithm.BLAKE2B).forEach { hash ->
            val startNs = System.nanoTime()
            val error = assertThrows(UnsupportedOperationException::class.java) {
                provider.createSuite(
                    NoiseCryptoAlgorithms(
                        dh = NoiseDhAlgorithm.X25519,
                        aead = NoiseAeadAlgorithm.AES_GCM,
                        hash = hash
                    )
                )
            }
            val elapsedNs = System.nanoTime() - startNs
            assertTrue(error.message.orEmpty().contains(hash.name))
            println(
                "benchmark noise-crypto unsupported hash=${hash.name.lowercase()} elapsed_ns=$elapsedNs " +
                    "message=${error.message.orEmpty()}"
            )
        }
    }

    private fun runHandshakeRounds(
        suite: NoiseCryptoSuite,
        pattern: HandshakePattern,
        algorithms: NoiseCryptoAlgorithms,
        rounds: Int,
        fixture: HandshakeFixture
    ): Long {
        var checksum = 0L
        repeat(rounds) { round ->
            val initiatorStatic = fixture.initiatorStatic[round]
            val responderStatic = fixture.responderStatic[round]
            val initiatorEphemeral = fixture.initiatorEphemeral[round]
            val responderEphemeral = fixture.responderEphemeral[round]

            val initiator = HandshakeState.initialize(
                pattern = pattern,
                role = HandshakeRole.INITIATOR,
                cryptoSuite = suite,
                localStatic = initiatorStatic,
                remoteStatic = responderStatic.publicKey,
                ephemeralKeyGenerator = { initiatorEphemeral }
            )
            val responder = HandshakeState.initialize(
                pattern = pattern,
                role = HandshakeRole.RESPONDER,
                cryptoSuite = suite,
                localStatic = responderStatic,
                remoteStatic = initiatorStatic.publicKey,
                ephemeralKeyGenerator = { responderEphemeral }
            )

            pattern.messages.forEachIndexed { messageIndex, messagePattern ->
                val payload = byteArrayOf(
                    pattern.ordinal.toByte(),
                    algorithms.aead.ordinal.toByte(),
                    algorithms.hash.ordinal.toByte(),
                    (round and 0xFF).toByte(),
                    messageIndex.toByte()
                )
                val (sender, receiver) = if (messagePattern.direction == MessageDirection.INITIATOR_TO_RESPONDER) {
                    initiator to responder
                } else {
                    responder to initiator
                }
                val message = sender.writeMessage(payload)
                assertArrayEquals(payload, receiver.readMessage(message))
            }

            assertTrue(initiator.isComplete())
            assertTrue(responder.isComplete())
            assertArrayEquals(initiator.handshakeHash(), responder.handshakeHash())

            val (initiatorTx, initiatorRx) = initiator.splitTransportStates()
            val (responderTx, responderRx) = responder.splitTransportStates()
            assertArrayEquals(requireNotNull(initiatorTx.keyMaterial()), requireNotNull(responderRx.keyMaterial()))
            assertArrayEquals(requireNotNull(initiatorRx.keyMaterial()), requireNotNull(responderTx.keyMaterial()))

            checksum +=
                (initiator.handshakeHash()[0].toInt() and 0xFF) +
                (initiator.handshakeHash()[1].toInt() and 0xFF) +
                pattern.messages.size
        }
        return checksum
    }

    private fun runHashAndHkdfLoops(
        suite: NoiseCryptoSuite,
        iterations: Int,
        expectedHashLength: Int
    ): Long {
        var checksum = 0L
        repeat(iterations) { iteration ->
            val input = byteArrayOf(
                (iteration and 0xFF).toByte(),
                ((iteration shr 8) and 0xFF).toByte(),
                0x5A.toByte()
            )
            val digest = suite.hash.hash(input)
            assertEquals(expectedHashLength, digest.size)

            val hkdfOutputs = suite.keyDerivation.hkdf(
                chainingKey = digest,
                inputKeyMaterial = input,
                outputs = 2
            )
            assertEquals(2, hkdfOutputs.size)
            hkdfOutputs.forEach { output -> assertEquals(expectedHashLength, output.size) }

            checksum +=
                (digest[0].toInt() and 0xFF) +
                (hkdfOutputs[0][0].toInt() and 0xFF) +
                (hkdfOutputs[1][0].toInt() and 0xFF)
        }
        return checksum
    }

    private fun runDhLoops(
        diffieHellman: NoiseDiffieHellmanFunction,
        keyPairs: List<NoiseKeyPair>,
        iterations: Int
    ): Long {
        var checksum = 0L
        repeat(iterations) { index ->
            val alice = keyPairs[index]
            val bob = keyPairs[index + 1]
            val aliceShared = diffieHellman.dh(alice.privateKey, bob.publicKey)
            val bobShared = diffieHellman.dh(bob.privateKey, alice.publicKey)
            assertArrayEquals(aliceShared, bobShared)
            assertEquals(32, aliceShared.size)
            checksum += (aliceShared[0].toInt() and 0xFF) + (aliceShared[1].toInt() and 0xFF)
        }
        return checksum
    }

    private data class HandshakeFixture(
        val initiatorStatic: List<NoiseKeyPair>,
        val responderStatic: List<NoiseKeyPair>,
        val initiatorEphemeral: List<NoiseKeyPair>,
        val responderEphemeral: List<NoiseKeyPair>
    ) {
        companion object {
            fun generate(diffieHellman: NoiseDiffieHellmanFunction, rounds: Int): HandshakeFixture {
                return HandshakeFixture(
                    initiatorStatic = List(rounds) { diffieHellman.generateKeyPair() },
                    responderStatic = List(rounds) { diffieHellman.generateKeyPair() },
                    initiatorEphemeral = List(rounds) { diffieHellman.generateKeyPair() },
                    responderEphemeral = List(rounds) { diffieHellman.generateKeyPair() }
                )
            }
        }
    }
}
