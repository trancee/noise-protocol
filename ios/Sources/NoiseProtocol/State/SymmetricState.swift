import CryptoKit
import Foundation

/// Wraps CipherState with chaining key and handshake hash.
public final class SymmetricState: @unchecked Sendable {
    private var ck: Data
    private var h: Data
    private let cipherState: CipherState
    /// True if the handshake uses PSK mode (modifies "e" token processing).
    internal var hasPSK: Bool = false

    public init() {
        ck = Data()
        h = Data()
        cipherState = CipherState()
    }

    public func initializeSymmetric(protocolName: String) {
        let nameData = Data(protocolName.utf8)
        if nameData.count <= NoiseHash.hashlen {
            h = nameData + Data(repeating: 0, count: NoiseHash.hashlen - nameData.count)
        } else {
            h = NoiseHash.hash(nameData)
        }
        ck = h
        cipherState.initializeKey(nil)
    }

    public func mixKey(_ inputKeyMaterial: Data) {
        let outputs = NoiseHash.hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 2)
        ck = outputs[0]
        var tempK = outputs[1]
        // If HASHLEN is 64, truncate to 32. For SHA-256 (HASHLEN=32), no truncation needed.
        if NoiseHash.hashlen == 64 {
            tempK = tempK.prefix(32)
        }
        cipherState.initializeKey(tempK)
    }

    public func mixHash(_ data: Data) {
        h = NoiseHash.hash(h + data)
    }

    /// Used for PSK mode. Mixes key material into ck, h, and cipher key.
    public func mixKeyAndHash(_ inputKeyMaterial: Data) {
        let outputs = NoiseHash.hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 3)
        ck = outputs[0]
        mixHash(outputs[1])
        var tempK = outputs[2]
        if NoiseHash.hashlen == 64 {
            tempK = tempK.prefix(32)
        }
        cipherState.initializeKey(tempK)
    }

    public func getHandshakeHash() -> Data { h }

    /// Encrypts plaintext using h as AD, then mixes ciphertext into h.
    public func encryptAndHash(_ plaintext: Data) throws -> Data {
        let ciphertext = try cipherState.encryptWithAd(h, plaintext: plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    /// Decrypts ciphertext using h as AD, then mixes ciphertext into h.
    public func decryptAndHash(_ ciphertext: Data) throws -> Data {
        let plaintext = try cipherState.decryptWithAd(h, ciphertext: ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    /// Splits the symmetric state into two CipherStates for transport.
    /// c1 encrypts initiator→responder, c2 encrypts responder→initiator.
    public func split() -> (CipherState, CipherState) {
        let outputs = NoiseHash.hkdf(chainingKey: ck, inputKeyMaterial: Data(), numOutputs: 2)
        var tempK1 = outputs[0]
        var tempK2 = outputs[1]
        if NoiseHash.hashlen == 64 {
            tempK1 = tempK1.prefix(32)
            tempK2 = tempK2.prefix(32)
        }
        let c1 = CipherState()
        let c2 = CipherState()
        c1.initializeKey(tempK1)
        c2.initializeKey(tempK2)
        return (c1, c2)
    }

    internal var hasKey: Bool { cipherState.hasKey }
}
