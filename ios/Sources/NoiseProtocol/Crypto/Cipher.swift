import CryptoKit
import Foundation

/// ChaCha20-Poly1305 AEAD cipher for Noise protocol.
/// Nonce format: 4 zero bytes + 8 bytes little-endian counter.
public enum NoiseCipher {
    /// AEAD encrypt. Returns ciphertext || 16-byte tag.
    public static func encrypt(k: SymmetricKey, n: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let nonce = try makeNonce(n)
        let sealedBox = try ChaChaPoly.seal(
            plaintext,
            using: k,
            nonce: nonce,
            authenticating: ad
        )
        return sealedBox.ciphertext + sealedBox.tag
    }

    /// AEAD decrypt. Throws on authentication failure.
    public static func decrypt(k: SymmetricKey, n: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw NoiseError.decryptionFailed }
        let nonce = try makeNonce(n)
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: ct,
            tag: tag
        )
        return try ChaChaPoly.open(sealedBox, using: k, authenticating: ad)
    }

    /// ChaChaPoly nonce: 4 zero bytes + 8 bytes little-endian n.
    private static func makeNonce(_ n: UInt64) throws -> ChaChaPoly.Nonce {
        var bytes = [UInt8](repeating: 0, count: 4)
        withUnsafeBytes(of: n.littleEndian) { bytes.append(contentsOf: $0) }
        return try ChaChaPoly.Nonce(data: bytes)
    }
}
