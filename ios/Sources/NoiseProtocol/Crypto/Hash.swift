import CryptoKit
import Foundation

/// SHA-256 based hash functions for Noise protocol.
public enum NoiseHash {
    public static let hashlen = 32
    public static let blocklen = 64

    public static func hash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public static func hmacHash(key: Data, data: Data) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(
            for: data,
            using: SymmetricKey(data: key)
        )
        return Data(hmac)
    }

    /// HKDF per Noise spec: chaining_key as salt, input_key_material as IKM.
    /// Returns 2 or 3 outputs of HASHLEN bytes.
    public static func hkdf(
        chainingKey: Data,
        inputKeyMaterial: Data,
        numOutputs: Int
    ) -> [Data] {
        let tempKey = hmacHash(key: chainingKey, data: inputKeyMaterial)
        let output1 = hmacHash(key: tempKey, data: Data([0x01]))
        let output2 = hmacHash(key: tempKey, data: output1 + Data([0x02]))
        if numOutputs == 2 { return [output1, output2] }
        let output3 = hmacHash(key: tempKey, data: output2 + Data([0x03]))
        return [output1, output2, output3]
    }
}
