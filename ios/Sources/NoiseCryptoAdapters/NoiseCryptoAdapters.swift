import Foundation
import NoiseCore

public struct NoiseKeyPair: Sendable, Equatable {
    public let privateKey: Data
    public let publicKey: Data

    public init(privateKey: Data, publicKey: Data) {
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}

public protocol NoiseDiffieHellmanAdapter: Sendable {
    var name: String { get }
    func generateKeyPair() throws -> NoiseKeyPair
    func sharedSecret(privateKey: Data, publicKey: Data) throws -> Data
}

public protocol NoiseCipherAdapter: Sendable {
    var name: String { get }
    func encrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        plaintext: Data
    ) throws -> Data
    func decrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        ciphertext: Data
    ) throws -> Data
}

public protocol NoiseHashAdapter: Sendable {
    var name: String { get }
    func hash(_ data: Data) -> Data
}

public struct NoiseCryptoSuiteDescriptor: Sendable, Equatable {
    public let protocolName: NoiseProtocolDescriptor
    public let diffieHellman: String
    public let cipher: String
    public let hash: String

    public init(
        protocolName: NoiseProtocolDescriptor,
        diffieHellman: String,
        cipher: String,
        hash: String
    ) {
        self.protocolName = protocolName
        self.diffieHellman = diffieHellman
        self.cipher = cipher
        self.hash = hash
    }
}

public struct NoiseAdapterCatalog: Sendable, Equatable {
    public var diffieHellman: [String]
    public var ciphers: [String]
    public var hashes: [String]

    public init(diffieHellman: [String], ciphers: [String], hashes: [String]) {
        self.diffieHellman = diffieHellman
        self.ciphers = ciphers
        self.hashes = hashes
    }

    public static let empty = NoiseAdapterCatalog(
        diffieHellman: [],
        ciphers: [],
        hashes: []
    )
}

public actor NoiseCryptoAdapterRegistry {
    private var catalog: NoiseAdapterCatalog

    public init(catalog: NoiseAdapterCatalog = .empty) {
        self.catalog = catalog
    }

    public func register(diffieHellman name: String) {
        catalog.diffieHellman.append(name)
    }

    public func register(cipher name: String) {
        catalog.ciphers.append(name)
    }

    public func register(hash name: String) {
        catalog.hashes.append(name)
    }

    public func snapshot() -> NoiseAdapterCatalog {
        catalog
    }
}
