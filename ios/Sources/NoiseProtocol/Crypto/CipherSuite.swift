import Foundation
import BlakeHash
import CBLAKE2

/// Bundles all cryptographic operations for a Noise cipher suite.
public struct CipherSuite: Sendable {
    public let dhName: String
    public let cipherName: String
    public let hashName: String
    public let dhlen: Int
    public let hashlen: Int
    public let blocklen: Int

    // DH operations
    public let generateKeyPair: @Sendable () -> NoiseKeyPair
    public let dh: @Sendable (NoiseKeyPair, Data) throws -> Data
    public let keyPairFromPrivate: @Sendable (Data) throws -> NoiseKeyPair

    // Cipher operations (key is raw Data, 32 bytes)
    public let encrypt: @Sendable (Data, UInt64, Data, Data) throws -> Data
    public let decrypt: @Sendable (Data, UInt64, Data, Data) throws -> Data

    // Hash operations
    public let hash: @Sendable (Data) -> Data
    public let hmacHash: @Sendable (Data, Data) -> Data

    // Optional native HKDF override (avoids intermediate Data allocations)
    internal let hkdfOverride: (@Sendable (Data, Data, Int) -> [Data])?

    /// HKDF derived from hmacHash, or native C implementation when available.
    public func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: Int) -> [Data] {
        if let native = hkdfOverride {
            return native(chainingKey, inputKeyMaterial, numOutputs)
        }
        let tempKey = hmacHash(chainingKey, inputKeyMaterial)
        let output1 = hmacHash(tempKey, hkdfCounter01)
        let output2 = hmacHash(tempKey, output1 + hkdfCounter02)
        if numOutputs == 2 { return [output1, output2] }
        let output3 = hmacHash(tempKey, output2 + hkdfCounter03)
        return [output1, output2, output3]
    }

    /// Construct full protocol name: "Noise_{pattern}_{dh}_{cipher}_{hash}"
    public func protocolName(pattern: String) -> String {
        "Noise_\(pattern)_\(dhName)_\(cipherName)_\(hashName)"
    }
}

// MARK: - HKDF counter constants (avoid per-call allocation)

private let hkdfCounter01 = Data([0x01])
private let hkdfCounter02 = Data([0x02])
private let hkdfCounter03 = Data([0x03])

// MARK: - DH helpers (shared across all suites)

private let _25519_generate: @Sendable () -> NoiseKeyPair = { NoiseKeyPair() }
private let _25519_dh: @Sendable (NoiseKeyPair, Data) throws -> Data = { kp, pub in
    try kp.dh(remotePublicKey: pub)
}
private let _25519_fromPrivate: @Sendable (Data) throws -> NoiseKeyPair = { data in
    try NoiseKeyPair(privateKeyData: data)
}

// MARK: - Cipher helpers

private let _chacha_encrypt: @Sendable (Data, UInt64, Data, Data) throws -> Data = { k, n, ad, pt in
    try NoiseCipher.encrypt(k: k, n: n, ad: ad, plaintext: pt)
}
private let _chacha_decrypt: @Sendable (Data, UInt64, Data, Data) throws -> Data = { k, n, ad, ct in
    try NoiseCipher.decrypt(k: k, n: n, ad: ad, ciphertext: ct)
}
private let _aesgcm_encrypt: @Sendable (Data, UInt64, Data, Data) throws -> Data = { k, n, ad, pt in
    try NoiseCipherAESGCM.encrypt(k: k, n: n, ad: ad, plaintext: pt)
}
private let _aesgcm_decrypt: @Sendable (Data, UInt64, Data, Data) throws -> Data = { k, n, ad, ct in
    try NoiseCipherAESGCM.decrypt(k: k, n: n, ad: ad, ciphertext: ct)
}

// MARK: - Hash helpers

private let _sha256_hash: @Sendable (Data) -> Data = { NoiseHash.hash($0) }
private let _sha256_hmac: @Sendable (Data, Data) -> Data = { NoiseHash.hmacHash(key: $0, data: $1) }
private let _sha512_hash: @Sendable (Data) -> Data = { NoiseHashSHA512.hash($0) }
private let _sha512_hmac: @Sendable (Data, Data) -> Data = { NoiseHashSHA512.hmacHash(key: $0, data: $1) }

private let _blake2s_hash: @Sendable (Data) -> Data = { input in
    var output = Data(count: 32)
    _ = input.withUnsafeBytes { inPtr in
        output.withUnsafeMutableBytes { outPtr in
            cblake2s(outPtr.baseAddress!, 32,
                     inPtr.baseAddress, inPtr.count)
        }
    }
    return output
}
private let _blake2s_hmac: @Sendable (Data, Data) -> Data = { key, data in
    var output = Data(count: 32)
    _ = key.withUnsafeBytes { keyPtr in
        data.withUnsafeBytes { dataPtr in
            output.withUnsafeMutableBytes { outPtr in
                cblake2s_hmac(outPtr.baseAddress!,
                              keyPtr.baseAddress, keyPtr.count,
                              dataPtr.baseAddress, dataPtr.count)
            }
        }
    }
    return output
}
private let _blake2b_hash: @Sendable (Data) -> Data = { input in
    var output = Data(count: 64)
    _ = input.withUnsafeBytes { inPtr in
        output.withUnsafeMutableBytes { outPtr in
            cblake2b(outPtr.baseAddress!, 64,
                     inPtr.baseAddress, inPtr.count)
        }
    }
    return output
}
private let _blake2b_hmac: @Sendable (Data, Data) -> Data = { key, data in
    var output = Data(count: 64)
    _ = key.withUnsafeBytes { keyPtr in
        data.withUnsafeBytes { dataPtr in
            output.withUnsafeMutableBytes { outPtr in
                cblake2b_hmac(outPtr.baseAddress!,
                              keyPtr.baseAddress, keyPtr.count,
                              dataPtr.baseAddress, dataPtr.count)
            }
        }
    }
    return output
}

// MARK: - Native HKDF overrides for BLAKE2 (avoids intermediate Data allocations)

private let _blake2s_hkdf: @Sendable (Data, Data, Int) -> [Data] = { ck, ikm, numOutputs in
    var out1 = Data(count: 32)
    var out2 = Data(count: 32)
    if numOutputs == 2 {
        _ = ck.withUnsafeBytes { ckPtr in
            ikm.withUnsafeBytes { ikmPtr in
                out1.withUnsafeMutableBytes { o1 in
                    out2.withUnsafeMutableBytes { o2 in
                        cblake2s_hkdf2(ckPtr.baseAddress, ckPtr.count,
                                       ikmPtr.baseAddress, ikmPtr.count,
                                       o1.baseAddress!, o2.baseAddress!)
                    }
                }
            }
        }
        return [out1, out2]
    }
    var out3 = Data(count: 32)
    _ = ck.withUnsafeBytes { ckPtr in
        ikm.withUnsafeBytes { ikmPtr in
            out1.withUnsafeMutableBytes { o1 in
                out2.withUnsafeMutableBytes { o2 in
                    out3.withUnsafeMutableBytes { o3 in
                        cblake2s_hkdf3(ckPtr.baseAddress, ckPtr.count,
                                       ikmPtr.baseAddress, ikmPtr.count,
                                       o1.baseAddress!, o2.baseAddress!, o3.baseAddress!)
                    }
                }
            }
        }
    }
    return [out1, out2, out3]
}

private let _blake2b_hkdf: @Sendable (Data, Data, Int) -> [Data] = { ck, ikm, numOutputs in
    var out1 = Data(count: 64)
    var out2 = Data(count: 64)
    if numOutputs == 2 {
        _ = ck.withUnsafeBytes { ckPtr in
            ikm.withUnsafeBytes { ikmPtr in
                out1.withUnsafeMutableBytes { o1 in
                    out2.withUnsafeMutableBytes { o2 in
                        cblake2b_hkdf2(ckPtr.baseAddress, ckPtr.count,
                                       ikmPtr.baseAddress, ikmPtr.count,
                                       o1.baseAddress!, o2.baseAddress!)
                    }
                }
            }
        }
        return [out1, out2]
    }
    var out3 = Data(count: 64)
    _ = ck.withUnsafeBytes { ckPtr in
        ikm.withUnsafeBytes { ikmPtr in
            out1.withUnsafeMutableBytes { o1 in
                out2.withUnsafeMutableBytes { o2 in
                    out3.withUnsafeMutableBytes { o3 in
                        cblake2b_hkdf3(ckPtr.baseAddress, ckPtr.count,
                                       ikmPtr.baseAddress, ikmPtr.count,
                                       o1.baseAddress!, o2.baseAddress!, o3.baseAddress!)
                    }
                }
            }
        }
    }
    return [out1, out2, out3]
}

// MARK: - 8 Cipher Suite constants

extension CipherSuite {
    /// Noise_XX_25519_ChaChaPoly_SHA256 — the default suite.
    public static let noise_25519_ChaChaPoly_SHA256 = CipherSuite(
        dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA256",
        dhlen: 32, hashlen: 32, blocklen: 64,
        generateKeyPair: _25519_generate, dh: _25519_dh, keyPairFromPrivate: _25519_fromPrivate,
        encrypt: _chacha_encrypt, decrypt: _chacha_decrypt,
        hash: _sha256_hash, hmacHash: _sha256_hmac,
        hkdfOverride: nil
    )

    /// Noise_XX_25519_ChaChaPoly_SHA512
    public static let noise_25519_ChaChaPoly_SHA512 = CipherSuite(
        dhName: "25519", cipherName: "ChaChaPoly", hashName: "SHA512",
        dhlen: 32, hashlen: 64, blocklen: 128,
        generateKeyPair: _25519_generate, dh: _25519_dh, keyPairFromPrivate: _25519_fromPrivate,
        encrypt: _chacha_encrypt, decrypt: _chacha_decrypt,
        hash: _sha512_hash, hmacHash: _sha512_hmac,
        hkdfOverride: nil
    )

    /// Noise_XX_25519_ChaChaPoly_BLAKE2s
    public static let noise_25519_ChaChaPoly_BLAKE2s = CipherSuite(
        dhName: "25519", cipherName: "ChaChaPoly", hashName: "BLAKE2s",
        dhlen: 32, hashlen: 32, blocklen: 64,
        generateKeyPair: _25519_generate, dh: _25519_dh, keyPairFromPrivate: _25519_fromPrivate,
        encrypt: _chacha_encrypt, decrypt: _chacha_decrypt,
        hash: _blake2s_hash, hmacHash: _blake2s_hmac,
        hkdfOverride: _blake2s_hkdf
    )

    /// Noise_XX_25519_ChaChaPoly_BLAKE2b
    public static let noise_25519_ChaChaPoly_BLAKE2b = CipherSuite(
        dhName: "25519", cipherName: "ChaChaPoly", hashName: "BLAKE2b",
        dhlen: 32, hashlen: 64, blocklen: 128,
        generateKeyPair: _25519_generate, dh: _25519_dh, keyPairFromPrivate: _25519_fromPrivate,
        encrypt: _chacha_encrypt, decrypt: _chacha_decrypt,
        hash: _blake2b_hash, hmacHash: _blake2b_hmac,
        hkdfOverride: _blake2b_hkdf
    )

    /// Noise_XX_25519_AESGCM_SHA256
    public static let noise_25519_AESGCM_SHA256 = CipherSuite(
        dhName: "25519", cipherName: "AESGCM", hashName: "SHA256",
        dhlen: 32, hashlen: 32, blocklen: 64,
        generateKeyPair: _25519_generate, dh: _25519_dh, keyPairFromPrivate: _25519_fromPrivate,
        encrypt: _aesgcm_encrypt, decrypt: _aesgcm_decrypt,
        hash: _sha256_hash, hmacHash: _sha256_hmac,
        hkdfOverride: nil
    )

    /// Noise_XX_25519_AESGCM_SHA512
    public static let noise_25519_AESGCM_SHA512 = CipherSuite(
        dhName: "25519", cipherName: "AESGCM", hashName: "SHA512",
        dhlen: 32, hashlen: 64, blocklen: 128,
        generateKeyPair: _25519_generate, dh: _25519_dh, keyPairFromPrivate: _25519_fromPrivate,
        encrypt: _aesgcm_encrypt, decrypt: _aesgcm_decrypt,
        hash: _sha512_hash, hmacHash: _sha512_hmac,
        hkdfOverride: nil
    )

    /// Noise_XX_25519_AESGCM_BLAKE2s
    public static let noise_25519_AESGCM_BLAKE2s = CipherSuite(
        dhName: "25519", cipherName: "AESGCM", hashName: "BLAKE2s",
        dhlen: 32, hashlen: 32, blocklen: 64,
        generateKeyPair: _25519_generate, dh: _25519_dh, keyPairFromPrivate: _25519_fromPrivate,
        encrypt: _aesgcm_encrypt, decrypt: _aesgcm_decrypt,
        hash: _blake2s_hash, hmacHash: _blake2s_hmac,
        hkdfOverride: _blake2s_hkdf
    )

    /// Noise_XX_25519_AESGCM_BLAKE2b
    public static let noise_25519_AESGCM_BLAKE2b = CipherSuite(
        dhName: "25519", cipherName: "AESGCM", hashName: "BLAKE2b",
        dhlen: 32, hashlen: 64, blocklen: 128,
        generateKeyPair: _25519_generate, dh: _25519_dh, keyPairFromPrivate: _25519_fromPrivate,
        encrypt: _aesgcm_encrypt, decrypt: _aesgcm_decrypt,
        hash: _blake2b_hash, hmacHash: _blake2b_hmac,
        hkdfOverride: _blake2b_hkdf
    )
}
