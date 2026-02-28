package noise.protocol.crypto

import noise.protocol.core.HandshakePattern
import noise.protocol.core.HandshakeRole
import noise.protocol.core.HandshakeState
import noise.protocol.core.MessageDirection
import noise.protocol.core.NoiseCryptoSuite
import noise.protocol.core.NoiseDiffieHellmanFunction
import noise.protocol.core.NoiseKeyPair
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

@Tag("benchmark")
class CryptoProviderBenchmarkTest {
    private val provider = CryptoProvider()

    @Test
    fun measuresHandshakeAcrossPatternsForAllCryptoVariations() {
        val patterns = listOf(
            HandshakePattern.NN,
            HandshakePattern.NK,
            HandshakePattern.KK,
            HandshakePattern.IK,
            HandshakePattern.XX
        )
        val variations = allVariations()
        val measuredRounds = 8

        variations.forEach { algorithms ->
            val suite = provider.createSuite(algorithms)
            patterns.forEach { pattern ->
                val warmup = HandshakeFixture.generate(suite.diffieHellman, rounds = 1)
                runHandshakeRounds(
                    suite = suite,
                    pattern = pattern,
                    algorithms = algorithms,
                    rounds = 1,
                    fixture = warmup
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
    fun measuresHashAndHkdfAcrossAllAlgorithms() {
        val hashes = listOf(
            NoiseHashAlgorithm.SHA256,
            NoiseHashAlgorithm.SHA512,
            NoiseHashAlgorithm.BLAKE2S,
            NoiseHashAlgorithm.BLAKE2B
        )
        val measuredIterations = 4_000

        hashes.forEach { hash ->
            val suite = provider.createSuite(
                NoiseCryptoAlgorithms(
                    dh = NoiseDhAlgorithm.X25519,
                    aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
                    hash = hash
                )
            )
            val expectedLength = when (hash) {
                NoiseHashAlgorithm.SHA256, NoiseHashAlgorithm.BLAKE2S -> 32
                NoiseHashAlgorithm.SHA512, NoiseHashAlgorithm.BLAKE2B -> 64
            }
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
    fun measuresDiffieHellmanAcrossSupportedAlgorithms() {
        listOf(
            NoiseDhAlgorithm.X25519 to 1_200,
            NoiseDhAlgorithm.X448 to 300
        ).forEach { (algorithm, iterations) ->
            val suite = provider.createSuite(
                NoiseCryptoAlgorithms(
                    dh = algorithm,
                    aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
                    hash = NoiseHashAlgorithm.SHA256
                )
            )
            val expectedLength = if (algorithm == NoiseDhAlgorithm.X25519) 32 else 56

            val warmupKeys = List(21) { suite.diffieHellman.generateKeyPair() }
            runDhLoops(
                diffieHellman = suite.diffieHellman,
                keyPairs = warmupKeys,
                iterations = 20,
                expectedLength = expectedLength
            )

            val keyPairs = List(iterations + 1) { suite.diffieHellman.generateKeyPair() }
            val startNs = System.nanoTime()
            val checksum = runDhLoops(
                diffieHellman = suite.diffieHellman,
                keyPairs = keyPairs,
                iterations = iterations,
                expectedLength = expectedLength
            )
            val elapsedNs = System.nanoTime() - startNs
            val nsPerOp = elapsedNs / iterations
            val opsPerSec = iterations * 1_000_000_000.0 / elapsedNs.toDouble()

            assertTrue(elapsedNs > 0L)
            assertTrue(checksum > 0L)
            println(
                "benchmark noise-crypto dh dh=${algorithm.name.lowercase()} iterations=$iterations " +
                    "elapsed_ns=$elapsedNs ns_per_op=$nsPerOp ops_per_s=$opsPerSec checksum=$checksum"
            )
        }
    }

    private fun allVariations(): List<NoiseCryptoAlgorithms> {
        val dhAlgorithms = listOf(NoiseDhAlgorithm.X25519, NoiseDhAlgorithm.X448)
        val aeadAlgorithms = listOf(NoiseAeadAlgorithm.CHACHA20_POLY1305, NoiseAeadAlgorithm.AES_GCM)
        val hashAlgorithms = listOf(
            NoiseHashAlgorithm.SHA256,
            NoiseHashAlgorithm.SHA512,
            NoiseHashAlgorithm.BLAKE2S,
            NoiseHashAlgorithm.BLAKE2B
        )
        val variations = ArrayList<NoiseCryptoAlgorithms>()
        dhAlgorithms.forEach { dh ->
            aeadAlgorithms.forEach { aead ->
                hashAlgorithms.forEach { hash ->
                    variations += NoiseCryptoAlgorithms(dh = dh, aead = aead, hash = hash)
                }
            }
        }
        return variations
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
                    algorithms.dh.ordinal.toByte(),
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
        iterations: Int,
        expectedLength: Int
    ): Long {
        var checksum = 0L
        repeat(iterations) { index ->
            val alice = keyPairs[index]
            val bob = keyPairs[index + 1]
            val aliceShared = diffieHellman.dh(alice.privateKey, bob.publicKey)
            val bobShared = diffieHellman.dh(bob.privateKey, alice.publicKey)
            assertArrayEquals(aliceShared, bobShared)
            assertEquals(expectedLength, aliceShared.size)
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
