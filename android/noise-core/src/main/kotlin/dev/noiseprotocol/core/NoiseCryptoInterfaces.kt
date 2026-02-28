package dev.noiseprotocol.core

data class NoiseKeyPair(
    val privateKey: ByteArray,
    val publicKey: ByteArray
)

interface NoiseHashFunction {
    val hashLength: Int

    fun hash(data: ByteArray): ByteArray
}

interface NoiseKeyDerivationFunction {
    fun hkdf(chainingKey: ByteArray, inputKeyMaterial: ByteArray, outputs: Int): List<ByteArray>
}

interface NoiseCipherFunction {
    fun encrypt(key: ByteArray, nonce: ULong, associatedData: ByteArray, plaintext: ByteArray): ByteArray

    fun decrypt(key: ByteArray, nonce: ULong, associatedData: ByteArray, ciphertext: ByteArray): ByteArray

    fun rekey(key: ByteArray): ByteArray
}

interface NoiseDiffieHellmanFunction {
    fun generateKeyPair(): NoiseKeyPair

    fun dh(localPrivateKey: ByteArray, remotePublicKey: ByteArray): ByteArray
}

interface NoiseCryptoSuite {
    val hash: NoiseHashFunction
    val keyDerivation: NoiseKeyDerivationFunction
    val cipher: NoiseCipherFunction
    val diffieHellman: NoiseDiffieHellmanFunction
}
