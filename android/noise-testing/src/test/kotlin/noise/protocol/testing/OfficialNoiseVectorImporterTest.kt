package noise.protocol.testing

import noise.protocol.core.HandshakeMessage
import noise.protocol.core.HandshakeToken
import noise.protocol.crypto.CryptoProvider
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Path
import java.util.HexFormat

class OfficialNoiseVectorImporterTest {
    private val importer = OfficialNoiseVectorImporter(CryptoProvider())
    private val harness = NoiseTestHarness(CryptoProvider())

    @Test
    fun importsOfficialNoiseNnVectorIntoPassingSharedFixture() {
        val fixture = importer.importVector(OFFICIAL_NN_VECTOR_DOCUMENT, index = 0)

        assertEquals("noise-nn-25519-chachapoly-sha256", fixture.vectorId)
        assertEquals("Noise_NN_25519_ChaChaPoly_SHA256", fixture.protocol.name)
        assertEquals(2, fixture.inputs.payloads.size)
        assertEquals(2, fixture.expected.handshakeMessages.size)
        assertEquals(2, fixture.negativeCases.size)
        assertEquals("flip-tag-final-message", fixture.negativeCases.first().id)

        val result = harness.runDeterministic(fixture)
        assertEquals(true, result.passed)
        assertArrayEquals(fixture.expected.handshakeHash, result.handshakeHash)
        assertArrayEquals(
            fixture.expected.splitTransportKeys.initiator.tx,
            result.transportKeys?.initiatorTx
        )
    }

      @Test
      fun importsOfficialNoiseNnBlake2sVectorIntoEquivalentSharedArtifacts() {
        val fixture = harness.loadFixture(sharedFixturePath("noise-nn-25519-chachapoly-blake2s.json"))

        val imported = importer.importVector(
          OFFICIAL_NN_BLAKE2S_VECTOR_DOCUMENT,
          index = 0
        )

        assertEquivalentFixtureArtifacts(expected = fixture, actual = imported)
      }

      @Test
      fun importsOfficialNoiseNnpsk0VectorIntoEquivalentSharedArtifacts() {
        val fixture = harness.loadFixture(sharedFixturePath("noise-nnpsk0-25519-chachapoly-sha256.json"))

        val imported = importer.importVector(
          officialDocumentFromFixture(
            fixture = fixture,
            initiatorPskField = "init_psk",
            responderPskField = "resp_psk"
          ),
          index = 0
        )

        assertEquivalentFixtureArtifacts(expected = fixture, actual = imported)
      }

      @Test
      fun importsOfficialNoiseXxpsk2VectorWithPluralPskFieldsIntoEquivalentSharedArtifacts() {
        val fixture = harness.loadFixture(sharedFixturePath("noise-xxpsk2-25519-chachapoly-sha256.json"))

        val imported = importer.importVector(
          officialDocumentFromFixture(
            fixture = fixture,
            initiatorPskField = "init_psks",
            responderPskField = "resp_psks"
          ),
          index = 0
        )

        assertEquivalentFixtureArtifacts(expected = fixture, actual = imported)
      }

    @Test
    fun rejectsOfficialFallbackVectorsForSharedV1Contract() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(OFFICIAL_FALLBACK_VECTOR_DOCUMENT, index = 0)
        }

        assertEquals(
            "Official Noise fallback vectors are not representable by the shared v1 fixture contract.",
            error.message
        )
    }

        @Test
        fun rejectsOfficialHybridVectorsForSharedV1Contract() {
          val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(OFFICIAL_HYBRID_VECTOR_DOCUMENT, index = 0)
          }

          assertEquals(
            "Official Noise hybrid vectors are not representable by the shared v1 fixture contract.",
            error.message
          )
        }

        @Test
        fun rejectsOfficialVectorsWithAsymmetricPrologues() {
          val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(OFFICIAL_ASYMMETRIC_PROLOGUE_DOCUMENT, index = 0)
          }

          assertEquals(
            "Official Noise vectors with asymmetric initiator/responder prologues are not representable by the shared v1 fixture contract.",
            error.message
          )
        }

        @Test
        fun rejectsOfficialVectorsWithMismatchedPskValues() {
          val fixture = harness.loadFixture(sharedFixturePath("noise-nnpsk0-25519-chachapoly-sha256.json"))
          val psk = HEX.formatHex(fixture.inputs.preSharedKeys.getValue(0))
          val mismatchedDocument = officialDocumentFromFixture(
            fixture = fixture,
            initiatorPskField = "init_psk",
            responderPskField = "resp_psk"
          ).replace("\"resp_psk\": \"$psk\"", "\"resp_psk\": \"${mutateHex(psk)}\"")

          val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(mismatchedDocument, index = 0)
          }

          assertEquals(
            "Official Noise PSK arrays differ between initiator and responder; shared v1 fixtures store a single agreed PSK set.",
            error.message
          )
        }

        @Test
        fun rejectsOfficialVectorsWithMismatchedPskCounts() {
          val fixture = harness.loadFixture(sharedFixturePath("noise-xxpsk2-25519-chachapoly-sha256.json"))
          val psk = HEX.formatHex(fixture.inputs.preSharedKeys.getValue(2))
          val mismatchedDocument = officialDocumentFromFixture(
            fixture = fixture,
            initiatorPskField = "init_psks",
            responderPskField = "resp_psks"
          ).replace("\"resp_psks\": [\"$psk\"]", "\"resp_psks\": []")

          val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(mismatchedDocument, index = 0)
          }

          assertEquals(
            "Official Noise PSK arrays must match for both parties to translate into the shared v1 fixture contract.",
            error.message
          )
        }

        @Test
        fun rejectsOfficialVectorsWithMismatchedInitRemoteStatic() {
          val fixture = harness.loadFixture(sharedFixturePath("noise-xxpsk2-25519-chachapoly-sha256.json"))
          val responderEphemeral = HEX.formatHex(fixture.inputs.keyMaterial.responder.ephemeralKey.privateKey)
          val responderPublic = HEX.formatHex(fixture.inputs.keyMaterial.responder.staticKey.publicKey)
          val mismatchedDocument = officialDocumentFromFixture(
            fixture = fixture,
            initiatorPskField = "init_psks",
            responderPskField = "resp_psks"
          ).replace(
            "\"resp_ephemeral\": \"$responderEphemeral\",",
            "\"resp_ephemeral\": \"$responderEphemeral\",\n              \"init_remote_static\": \"${mutateHex(responderPublic)}\","
          )

          val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(mismatchedDocument, index = 0)
          }

          assertEquals(
            "Official init_remote_static does not match the responder static public key derived for Noise_XXpsk2_25519_ChaChaPoly_SHA256.",
            error.message
          )
        }

        @Test
        fun rejectsOfficialVectorsWithMismatchedRespRemoteStatic() {
          val fixture = harness.loadFixture(sharedFixturePath("noise-xxpsk2-25519-chachapoly-sha256.json"))
          val responderEphemeral = HEX.formatHex(fixture.inputs.keyMaterial.responder.ephemeralKey.privateKey)
          val initiatorPublic = HEX.formatHex(fixture.inputs.keyMaterial.initiator.staticKey.publicKey)
          val mismatchedDocument = officialDocumentFromFixture(
            fixture = fixture,
            initiatorPskField = "init_psks",
            responderPskField = "resp_psks"
          ).replace(
            "\"resp_ephemeral\": \"$responderEphemeral\",",
            "\"resp_ephemeral\": \"$responderEphemeral\",\n              \"resp_remote_static\": \"${mutateHex(initiatorPublic)}\","
          )

          val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(mismatchedDocument, index = 0)
          }

          assertEquals(
            "Official resp_remote_static does not match the initiator static public key derived for Noise_XXpsk2_25519_ChaChaPoly_SHA256.",
            error.message
          )
        }

        @Test
        fun rejectsOfficialVectorsWithMismatchedHandshakeCiphertext() {
          val fixture = harness.loadFixture(sharedFixturePath("noise-xxpsk2-25519-chachapoly-sha256.json"))
          val originalCiphertext = rawCiphertextHex(
            fixture = fixture,
            messageIndex = 1,
            encodedMessage = fixture.expected.handshakeMessages.first { it.index == 1 }.message
          )
          val mismatchedDocument = officialDocumentFromFixture(
            fixture = fixture,
            initiatorPskField = "init_psks",
            responderPskField = "resp_psks"
          ).replace("\"ciphertext\": \"$originalCiphertext\"", "\"ciphertext\": \"${mutateHex(originalCiphertext)}\"")

          val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(mismatchedDocument, index = 0)
          }

          assertEquals(
            "Translated official Noise vector handshake message 1 for Noise_XXpsk2_25519_ChaChaPoly_SHA256 does not match the official ciphertext.",
            error.message
          )
        }

        @Test
        fun rejectsOfficialVectorsWithMismatchedHandshakeHash() {
          val fixture = harness.loadFixture(sharedFixturePath("noise-xxpsk2-25519-chachapoly-sha256.json"))
          val handshakeHash = HEX.formatHex(fixture.expected.handshakeHash)
          val mismatchedDocument = officialDocumentFromFixture(
            fixture = fixture,
            initiatorPskField = "init_psks",
            responderPskField = "resp_psks"
          ).replace("\"handshake_hash\": \"$handshakeHash\"", "\"handshake_hash\": \"${mutateHex(handshakeHash)}\"")

          val error = assertThrows(IllegalArgumentException::class.java) {
            importer.importVector(mismatchedDocument, index = 0)
          }

          assertEquals(
            "Translated official Noise vector handshake hash for Noise_XXpsk2_25519_ChaChaPoly_SHA256 does not match the official handshake_hash.",
            error.message
          )
        }

        private fun assertEquivalentFixtureArtifacts(expected: NoiseVectorFixture, actual: NoiseVectorFixture) {
          assertEquals(expected.vectorId, actual.vectorId)
          assertEquals(expected.protocol.name, actual.protocol.name)
          assertEquals(expected.protocol.pattern, actual.protocol.pattern)
          assertEquals(expected.protocol.suite, actual.protocol.suite)
          assertArrayEquals(expected.inputs.prologue, actual.inputs.prologue)

          assertKeyMaterialEquals(expected.inputs.keyMaterial.initiator, actual.inputs.keyMaterial.initiator)
          assertKeyMaterialEquals(expected.inputs.keyMaterial.responder, actual.inputs.keyMaterial.responder)

          assertEquals(expected.inputs.preSharedKeys.keys, actual.inputs.preSharedKeys.keys)
          expected.inputs.preSharedKeys.keys.sorted().forEach { placement ->
            assertArrayEquals(expected.inputs.preSharedKeys.getValue(placement), actual.inputs.preSharedKeys.getValue(placement))
          }

          assertEquals(expected.inputs.payloads.size, actual.inputs.payloads.size)
          expected.inputs.payloads.zip(actual.inputs.payloads).forEach { (expectedPayload, actualPayload) ->
            assertEquals(expectedPayload.index, actualPayload.index)
            assertEquals(expectedPayload.sender, actualPayload.sender)
            assertArrayEquals(expectedPayload.plaintext, actualPayload.plaintext)
          }

          assertEquals(expected.expected.handshakeMessages.size, actual.expected.handshakeMessages.size)
          expected.expected.handshakeMessages.zip(actual.expected.handshakeMessages).forEach { (expectedMessage, actualMessage) ->
            assertEquals(expectedMessage.index, actualMessage.index)
            assertEquals(expectedMessage.sender, actualMessage.sender)
            assertArrayEquals(expectedMessage.message, actualMessage.message)
          }

          assertArrayEquals(expected.expected.handshakeHash, actual.expected.handshakeHash)
          assertArrayEquals(expected.expected.splitTransportKeys.initiator.tx, actual.expected.splitTransportKeys.initiator.tx)
          assertArrayEquals(expected.expected.splitTransportKeys.initiator.rx, actual.expected.splitTransportKeys.initiator.rx)
          assertArrayEquals(expected.expected.splitTransportKeys.responder.tx, actual.expected.splitTransportKeys.responder.tx)
          assertArrayEquals(expected.expected.splitTransportKeys.responder.rx, actual.expected.splitTransportKeys.responder.rx)

          val result = harness.runDeterministic(actual)
          assertEquals(true, result.passed)
        }

        private fun assertKeyMaterialEquals(expected: VectorPartyKeyMaterial, actual: VectorPartyKeyMaterial) {
          assertArrayEquals(expected.staticKey.publicKey, actual.staticKey.publicKey)
          assertArrayEquals(expected.ephemeralKey.publicKey, actual.ephemeralKey.publicKey)
          assertEquals(expected.staticKey.privateKey.size, actual.staticKey.privateKey.size)
          assertEquals(expected.ephemeralKey.privateKey.size, actual.ephemeralKey.privateKey.size)
        }

        private fun officialDocumentFromFixture(
          fixture: NoiseVectorFixture,
          initiatorPskField: String,
          responderPskField: String
        ): String {
          val handshakeMessagesByIndex = fixture.expected.handshakeMessages.sortedBy { it.index }
          val payloadsByIndex = fixture.inputs.payloads.sortedBy { it.index }
          val initiatorPsks = fixture.inputs.preSharedKeys.keys.sorted().map { placement ->
            HEX.formatHex(fixture.inputs.preSharedKeys.getValue(placement))
          }

          val messagesJson = handshakeMessagesByIndex.zip(payloadsByIndex).joinToString(",\n") { (message, payload) ->
            val rawCiphertext = rawCiphertextHex(fixture, message.index, message.message)
            """
              {
                  "payload": "${HEX.formatHex(payload.plaintext)}",
                  "ciphertext": "$rawCiphertext"
              }
            """.trimIndent()
          }

          val initiatorPsksJson = pskFieldJson(initiatorPskField, initiatorPsks)
          val responderPsksJson = pskFieldJson(responderPskField, initiatorPsks)

          return """
          {
            "vectors": [
              {
              "protocol_name": "${fixture.protocol.name}",
              "init_prologue": "${HEX.formatHex(fixture.inputs.prologue)}",
              "init_static": "${HEX.formatHex(fixture.inputs.keyMaterial.initiator.staticKey.privateKey)}",
              "init_ephemeral": "${HEX.formatHex(fixture.inputs.keyMaterial.initiator.ephemeralKey.privateKey)}",
              "resp_prologue": "${HEX.formatHex(fixture.inputs.prologue)}",
              "resp_static": "${HEX.formatHex(fixture.inputs.keyMaterial.responder.staticKey.privateKey)}",
              "resp_ephemeral": "${HEX.formatHex(fixture.inputs.keyMaterial.responder.ephemeralKey.privateKey)}",
              "handshake_hash": "${HEX.formatHex(fixture.expected.handshakeHash)}",
              $initiatorPsksJson,
              $responderPsksJson,
              "messages": [
                $messagesJson
              ]
            }
            ]
          }
          """.trimIndent()
        }

        private fun pskFieldJson(fieldName: String, psks: List<String>): String {
          return when (fieldName) {
            "init_psk", "resp_psk" -> "\"$fieldName\": \"${psks.single()}\""
            "init_psks", "resp_psks" -> {
              val array = psks.joinToString(", ") { "\"$it\"" }
              "\"$fieldName\": [$array]"
            }
            else -> error("Unsupported PSK field name '$fieldName'.")
          }
        }

        private fun mutateHex(value: String): String {
          val replacement = if (value.startsWith("00")) "ff" else "00"
          return replacement + value.drop(2)
        }

        private fun rawCiphertextHex(fixture: NoiseVectorFixture, messageIndex: Int, encodedMessage: ByteArray): String {
          val expectedTokens = fixture.protocol.pattern.messages[messageIndex].tokens.filter { token ->
            token == HandshakeToken.E || token == HandshakeToken.S
          }
          val decoded = HandshakeMessage.decode(
            direction = fixture.protocol.pattern.messages[messageIndex].direction,
            expectedTokens = expectedTokens,
            encoded = encodedMessage
          )
          return HEX.formatHex(decoded.rawMessageBytes())
        }

        private fun HandshakeMessage.rawMessageBytes(): ByteArray {
          val size = tokenValues.sumOf { it.data.size } + payload.size
          val raw = ByteArray(size)
          var offset = 0
          tokenValues.forEach { tokenValue ->
            tokenValue.data.copyInto(raw, destinationOffset = offset)
            offset += tokenValue.data.size
          }
          payload.copyInto(raw, destinationOffset = offset)
          return raw
        }

        private fun sharedFixturePath(fileName: String): Path {
          return sharedFixtureDirectory().resolve(fileName)
        }

        private fun sharedFixtureDirectory(): Path {
          val userDir = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
          val candidates = listOf(
            userDir.resolve("../test-vectors/fixtures/v1").normalize(),
            userDir.resolve("../../test-vectors/fixtures/v1").normalize(),
            userDir.resolve("test-vectors/fixtures/v1").normalize()
          )

          return candidates.firstOrNull(Files::exists)
            ?: error("Unable to resolve shared vector fixture directory from $userDir")
        }

    companion object {
          val HEX: HexFormat = HexFormat.of()

        const val OFFICIAL_NN_VECTOR_DOCUMENT = """
        {
          "vectors": [
            {
              "protocol_name": "Noise_NN_25519_ChaChaPoly_SHA256",
              "init_prologue": "50726f6c6f6775652d7631",
              "init_static": null,
              "init_ephemeral": "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
              "resp_prologue": "50726f6c6f6775652d7631",
              "resp_static": null,
              "resp_ephemeral": "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
              "handshake_hash": "0cdc4eae809d187a4750de10df59c29e4a026edf95727efaeb18b569ebf9bf8f",
              "messages": [
                {
                  "payload": "48656c6c6f",
                  "ciphertext": "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a48656c6c6f"
                },
                {
                  "payload": "776f726c64",
                  "ciphertext": "dc2cca31e8e43bbd91dff7e475cca3347eb478107d5bd765aba4ae4a30c35d448aa2198ed1ac9d712e7cfb5f3cc5e3202652d8e6d8"
                }
              ]
            }
          ]
        }
        """

        const val OFFICIAL_NN_BLAKE2S_VECTOR_DOCUMENT = """
        {
          "vectors": [
            {
              "protocol_name": "Noise_NN_25519_ChaChaPoly_BLAKE2s",
              "init_prologue": "70726f6c6f6775652d6e6f6973652d6e6e2d32353531392d636861636861706f6c792d626c616b653273",
              "init_static": "086fc4277975bbd4947e22475ab5513ff54cb2f3bf89bb313f60f7c7a286607b",
              "init_ephemeral": "90cbaef220ceb7df1d5e26cee5b8c0163768e11d51cdfcf86377d1c7c7045463",
              "resp_prologue": "70726f6c6f6775652d6e6f6973652d6e6e2d32353531392d636861636861706f6c792d626c616b653273",
              "resp_static": "3078ec6ed96923e57ef5f48865b18bd790d460150cfe790762f5bcd2f59d0250",
              "resp_ephemeral": "68ee4293572b7c17711e379a37671f77f8e7e054eb67a30b728d7df7ee159f54",
              "handshake_hash": "6a5002fb7157c5aa50160cefe7cd4438de01533a6de62fed6cff4a8c98ac278e",
              "messages": [
                {
                  "payload": "7061796c6f61642d302d6e6f6973652d6e6e2d32353531392d636861636861706f6c792d626c616b653273",
                  "ciphertext": "ec2b8b7c5aac02bfccfd673f042cdceab6227fd643d9e841d1ed1a80d1f5737d7061796c6f61642d302d6e6f6973652d6e6e2d32353531392d636861636861706f6c792d626c616b653273"
                },
                {
                  "payload": "7061796c6f61642d312d6e6f6973652d6e6e2d32353531392d636861636861706f6c792d626c616b653273",
                  "ciphertext": "24a44fe4dd1214fc51fec35b2235a36e4b1148bd6e8eee220d43765ebada7e555e71b097555814693f1a231f25acad2d26c093e05b78ddd2ff42713974c1cd058e4c59049decf9887bee1b5c71f3846911beae29050a14d4187c04"
                }
              ]
            }
          ]
        }
        """

        const val OFFICIAL_FALLBACK_VECTOR_DOCUMENT = """
        {
          "vectors": [
            {
              "protocol_name": "Noise_IK_25519_ChaChaPoly_SHA256",
              "fallback": true,
              "init_prologue": "00",
              "resp_prologue": "00",
              "messages": [
                {
                  "payload": "",
                  "ciphertext": ""
                }
              ]
            }
          ]
        }
        """

        const val OFFICIAL_HYBRID_VECTOR_DOCUMENT = """
        {
          "vectors": [
            {
              "protocol_name": "Noise_NN_25519_ChaChaPoly_SHA256",
              "hybrid": "NewHope",
              "init_prologue": "00",
              "resp_prologue": "00",
              "messages": [
                {
                  "payload": "",
                  "ciphertext": ""
                },
                {
                  "payload": "",
                  "ciphertext": ""
                }
              ]
            }
          ]
        }
        """

        const val OFFICIAL_ASYMMETRIC_PROLOGUE_DOCUMENT = """
        {
          "vectors": [
            {
              "protocol_name": "Noise_NN_25519_ChaChaPoly_SHA256",
              "init_prologue": "00",
              "resp_prologue": "01",
              "messages": [
                {
                  "payload": "",
                  "ciphertext": ""
                },
                {
                  "payload": "",
                  "ciphertext": ""
                }
              ]
            }
          ]
        }
        """
    }
}