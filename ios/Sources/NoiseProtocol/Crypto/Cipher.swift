import CryptoKit
import Foundation

/// ChaCha20-Poly1305 AEAD cipher for Noise protocol.
/// Nonce format: 4 zero bytes + 8 bytes little-endian counter.
public enum NoiseCipher {
    /// AEAD encrypt with raw key bytes. Returns ciphertext || 16-byte tag.
    public static func encrypt(k: Data, n: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let key = SymmetricKey(data: k)
        let nonce = try makeNonce(n)
        let sealedBox = try ChaChaPoly.seal(
            plaintext,
            using: key,
            nonce: nonce,
            authenticating: ad
        )
        return sealedBox.ciphertext + sealedBox.tag
    }

    /// AEAD decrypt with raw key bytes. Throws on authentication failure.
    public static func decrypt(k: Data, n: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw NoiseError.decryptionFailed }
        let key = SymmetricKey(data: k)
        let nonce = try makeNonce(n)
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: nonce,
            ciphertext: ct,
            tag: tag
        )
        return try ChaChaPoly.open(sealedBox, using: key, authenticating: ad)
    }

    /// ChaChaPoly nonce: 4 zero bytes + 8 bytes little-endian n.
    private static func makeNonce(_ n: UInt64) throws -> ChaChaPoly.Nonce {
        var bytes = [UInt8](repeating: 0, count: 4)
        withUnsafeBytes(of: n.littleEndian) { bytes.append(contentsOf: $0) }
        return try ChaChaPoly.Nonce(data: bytes)
    }
}

/// AES-256-GCM AEAD cipher for Noise protocol.
/// Nonce format: 4 zero bytes + 8 bytes BIG-ENDIAN counter.
public enum NoiseCipherAESGCM {
    /// AEAD encrypt. Returns ciphertext || 16-byte tag.
    public static func encrypt(k: Data, n: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let nonce = try makeNonce(n)
        let key = SymmetricKey(data: k)
        let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonce, authenticating: ad)
        return sealedBox.ciphertext + sealedBox.tag
    }

    /// AEAD decrypt. Throws on authentication failure.
    public static func decrypt(k: Data, n: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw NoiseError.decryptionFailed }
        let nonce = try makeNonce(n)
        let key = SymmetricKey(data: k)
        let tagStart = ciphertext.count - 16
        let ct = ciphertext.prefix(tagStart)
        let tag = ciphertext.suffix(16)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        return try AES.GCM.open(sealedBox, using: key, authenticating: ad)
    }

    /// AESGCM nonce: 4 zero bytes + 8 bytes BIG-ENDIAN n.
    private static func makeNonce(_ n: UInt64) throws -> AES.GCM.Nonce {
        var bytes = [UInt8](repeating: 0, count: 4)
        withUnsafeBytes(of: n.bigEndian) { bytes.append(contentsOf: $0) }
        return try AES.GCM.Nonce(data: bytes)
    }
}
