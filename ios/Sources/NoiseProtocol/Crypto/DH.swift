import CryptoKit
import Foundation

/// X25519 Diffie-Hellman key pair for Noise protocol operations.
public struct NoiseKeyPair: Sendable {
    public let privateKey: Curve25519.KeyAgreement.PrivateKey
    public let publicKey: Data

    public init() {
        self.privateKey = .init()
        self.publicKey = Data(privateKey.publicKey.rawRepresentation)
    }

    public init(privateKey: Curve25519.KeyAgreement.PrivateKey) {
        self.privateKey = privateKey
        self.publicKey = Data(privateKey.publicKey.rawRepresentation)
    }

    public init(privateKeyData: Data) throws {
        self.privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        self.publicKey = Data(self.privateKey.publicKey.rawRepresentation)
    }

    /// Perform X25519 Diffie-Hellman. Returns DHLEN (32) bytes.
    public func dh(remotePublicKey: Data) throws -> Data {
        let remotePub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remotePublicKey)
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: remotePub)
        return shared.withUnsafeBytes { Data($0) }
    }
}

/// Length in bytes of public keys and DH output.
public let DHLEN = 32

/// Protocol for key pair generation, allowing deterministic injection for testing.
public protocol KeyPairGenerator: Sendable {
    func generate() -> NoiseKeyPair
}

/// Generates random X25519 key pairs.
public struct RandomKeyPairGenerator: KeyPairGenerator {
    public init() {}
    public func generate() -> NoiseKeyPair { NoiseKeyPair() }
}

/// Generates a key pair from a fixed private key (for test vectors).
public struct DeterministicKeyPairGenerator: KeyPairGenerator {
    private let privateKeyData: Data

    public init(privateKeyData: Data) {
        self.privateKeyData = privateKeyData
    }

    public func generate() -> NoiseKeyPair {
        try! NoiseKeyPair(privateKeyData: privateKeyData)
    }
}
