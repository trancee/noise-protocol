package noise.protocol.core

class CipherState(
    private val cipherFunction: NoiseCipherFunction,
    initialKey: ByteArray? = null
) {
    private var key: ByteArray? = initialKey?.copyOf()

    var nonce: ULong = 0uL
        private set

    fun initializeKey(newKey: ByteArray?) {
        key = newKey?.copyOf()
        nonce = 0uL
    }

    fun hasKey(): Boolean = key != null

    fun keyMaterial(): ByteArray? = key?.copyOf()

    fun setNonce(value: ULong) {
        require(value >= nonce) { "Nonce must be monotonic." }
        nonce = value
    }

    fun encryptWithAd(associatedData: ByteArray, plaintext: ByteArray): ByteArray {
        val currentKey = key ?: return plaintext.copyOf()
        return cipherFunction.encrypt(
            key = currentKey,
            nonce = consumeNonce(),
            associatedData = associatedData,
            plaintext = plaintext
        )
    }

    fun decryptWithAd(associatedData: ByteArray, ciphertext: ByteArray): ByteArray {
        val currentKey = key ?: return ciphertext.copyOf()
        return cipherFunction.decrypt(
            key = currentKey,
            nonce = consumeNonce(),
            associatedData = associatedData,
            ciphertext = ciphertext
        )
    }

    fun rekey() {
        key = key?.let(cipherFunction::rekey)
    }

    private fun consumeNonce(): ULong {
        check(nonce != ULong.MAX_VALUE) { "CipherState nonce exhausted." }
        return nonce.also { nonce += 1uL }
    }
}
