import CryptoKit
import Foundation

/// Holds a cipher key and nonce counter for AEAD encryption/decryption.
public final class CipherState: @unchecked Sendable {
    private var k: SymmetricKey?
    private var n: UInt64 = 0

    public init() {}

    public func initializeKey(_ key: Data?) {
        k = key.map { SymmetricKey(data: $0) }
        n = 0
    }

    public var hasKey: Bool { k != nil }

    public func setNonce(_ nonce: UInt64) {
        n = nonce
    }

    public func getNonce() -> UInt64 { n }

    /// Encrypt with associated data. If no key is set, returns plaintext.
    public func encryptWithAd(_ ad: Data, plaintext: Data) throws -> Data {
        guard let key = k else { return plaintext }
        guard n < UInt64.max - 1 else { throw NoiseError.nonceExhausted }
        let ct = try NoiseCipher.encrypt(k: key, n: n, ad: ad, plaintext: plaintext)
        n += 1
        return ct
    }

    /// Decrypt with associated data. On failure, nonce is NOT incremented.
    public func decryptWithAd(_ ad: Data, ciphertext: Data) throws -> Data {
        guard let key = k else { return ciphertext }
        let pt: Data
        do {
            pt = try NoiseCipher.decrypt(k: key, n: n, ad: ad, ciphertext: ciphertext)
        } catch {
            throw NoiseError.decryptionFailed
        }
        n += 1
        return pt
    }

    /// Derives a new cipher key from the current one (one-way).
    public func rekey() throws {
        guard let key = k else { throw NoiseError.noKey }
        let zeros = Data(repeating: 0, count: 32)
        let newKeyData = try NoiseCipher.encrypt(
            k: key, n: UInt64.max, ad: Data(), plaintext: zeros
        ).prefix(32)
        k = SymmetricKey(data: newKeyData)
    }
}
