package noise.protocol.core

class SymmetricState(
    private val hashFunction: NoiseHashFunction,
    private val keyDerivationFunction: NoiseKeyDerivationFunction,
    private val cipherFunction: NoiseCipherFunction,
    protocolName: String
) {
    private var chainingKeyValue: ByteArray = hashFunction.hash(protocolName.encodeToByteArray())
    private var handshakeHashValue: ByteArray = chainingKeyValue.copyOf()
    private val cipherState = CipherState(cipherFunction)

    val chainingKey: ByteArray
        get() = chainingKeyValue.copyOf()

    val handshakeHash: ByteArray
        get() = handshakeHashValue.copyOf()

    fun hasCipherKey(): Boolean = cipherState.hasKey()

    fun mixHash(data: ByteArray) {
        handshakeHashValue = hashFunction.hash(handshakeHashValue + data)
    }

    fun mixKey(inputKeyMaterial: ByteArray) {
        val outputs = keyDerivationFunction.hkdf(chainingKeyValue, inputKeyMaterial, outputs = 2)
        require(outputs.size == 2) { "HKDF must return exactly 2 outputs for mixKey." }

        chainingKeyValue = outputs[0].copyOf()
        cipherState.initializeKey(outputs[1].copyOf(CIPHER_KEY_LENGTH))
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ciphertext = cipherState.encryptWithAd(handshakeHashValue, plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val plaintext = cipherState.decryptWithAd(handshakeHashValue, ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    fun split(): Pair<CipherState, CipherState> {
        val outputs = keyDerivationFunction.hkdf(chainingKeyValue, EMPTY_BYTE_ARRAY, outputs = 2)
        require(outputs.size == 2) { "HKDF must return exactly 2 outputs for split." }

        return CipherState(cipherFunction, outputs[0].copyOf(CIPHER_KEY_LENGTH)) to
            CipherState(cipherFunction, outputs[1].copyOf(CIPHER_KEY_LENGTH))
    }

    private companion object {
        const val CIPHER_KEY_LENGTH = 32
        val EMPTY_BYTE_ARRAY = ByteArray(0)
    }
}
