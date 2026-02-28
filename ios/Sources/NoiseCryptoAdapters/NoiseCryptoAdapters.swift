import CryptoKit
import Foundation
import NoiseCore

public typealias NoiseKeyPair = NoiseDHKeyPair

public protocol NoiseDiffieHellmanAdapter: NoiseDiffieHellmanAlgorithm {
    var name: String { get }
}

public protocol NoiseCipherAdapter: NoiseCipherAlgorithm {
    var name: String { get }
}

public protocol NoiseHashAdapter: NoiseHashAlgorithm {
    var name: String { get }
}

public enum NoiseCryptoAdapterError: Error, Sendable, Equatable {
    case unsupportedDiffieHellman(String)
    case unsupportedCipher(String)
    case unsupportedHash(String)
    case invalidKeyLength(algorithm: String, expected: Int, actual: Int)
    case invalidCiphertext(String)
}

public struct Curve25519DiffieHellmanAdapter: NoiseDiffieHellmanAdapter {
    private static let keyLength = 32

    public let name: String = "25519"

    public init() {}

    public func generateKeyPair() throws -> NoiseDHKeyPair {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        return NoiseDHKeyPair(
            privateKey: privateKey.rawRepresentation,
            publicKey: privateKey.publicKey.rawRepresentation
        )
    }

    public func dh(privateKey: Data, publicKey: Data) throws -> Data {
        guard privateKey.count == Self.keyLength else {
            throw NoiseCryptoAdapterError.invalidKeyLength(
                algorithm: name,
                expected: Self.keyLength,
                actual: privateKey.count
            )
        }

        do {
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            return sharedSecret.withUnsafeBytes { Data($0) }
        } catch {
            return Data(repeating: 0, count: Self.keyLength)
        }
    }
}

private enum NoiseNonceFormat {
    case littleEndianCounter
    case bigEndianCounter
}

private protocol NoiseAEADCipherAdapter: NoiseCipherAdapter {
    var nonceFormat: NoiseNonceFormat { get }
}

private extension NoiseAEADCipherAdapter {
    var keyLength: Int { 32 }

    func validate(key: Data, algorithm: String) throws {
        guard key.count == keyLength else {
            throw NoiseCryptoAdapterError.invalidKeyLength(
                algorithm: algorithm,
                expected: keyLength,
                actual: key.count
            )
        }
    }

    func noiseNonce(_ nonce: UInt64) -> Data {
        let counter: UInt64
        switch nonceFormat {
        case .littleEndianCounter:
            counter = nonce.littleEndian
        case .bigEndianCounter:
            counter = nonce.bigEndian
        }

        let counterBytes = withUnsafeBytes(of: counter) { Array($0) }
        var nonceData = Data(repeating: 0, count: 12)
        nonceData.replaceSubrange(4..<12, with: counterBytes)
        return nonceData
    }

    func derivedRekey(_ key: Data) throws -> Data {
        let ciphertext = try encrypt(
            key: key,
            nonce: UInt64.max,
            associatedData: Data(),
            plaintext: Data(repeating: 0, count: 32)
        )
        return Data(ciphertext.prefix(32))
    }
}

public struct ChaChaPolyCipherAdapter: NoiseAEADCipherAdapter {
    public let name: String = "ChaChaPoly"
    fileprivate let nonceFormat: NoiseNonceFormat = .littleEndianCounter

    public init() {}

    public func encrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        plaintext: Data
    ) throws -> Data {
        try validate(key: key, algorithm: name)
        let nonce = try ChaChaPoly.Nonce(data: noiseNonce(nonce))
        let sealedBox = try ChaChaPoly.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: nonce,
            authenticating: associatedData
        )
        return sealedBox.combined
    }

    public func decrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        ciphertext: Data
    ) throws -> Data {
        try validate(key: key, algorithm: name)
        let sealedBox = try ChaChaPoly.SealedBox(combined: ciphertext)
        return try ChaChaPoly.open(
            sealedBox,
            using: SymmetricKey(data: key),
            authenticating: associatedData
        )
    }

    public func rekey(_ key: Data) throws -> Data {
        try derivedRekey(key)
    }
}

public struct AESGCMCipherAdapter: NoiseAEADCipherAdapter {
    public let name: String = "AESGCM"
    fileprivate let nonceFormat: NoiseNonceFormat = .bigEndianCounter

    public init() {}

    public func encrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        plaintext: Data
    ) throws -> Data {
        try validate(key: key, algorithm: name)
        let nonce = try AES.GCM.Nonce(data: noiseNonce(nonce))
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: nonce,
            authenticating: associatedData
        )
        guard let combined = sealedBox.combined else {
            throw NoiseCryptoAdapterError.invalidCiphertext(name)
        }
        return combined
    }

    public func decrypt(
        key: Data,
        nonce: UInt64,
        associatedData: Data,
        ciphertext: Data
    ) throws -> Data {
        try validate(key: key, algorithm: name)
        let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
        return try AES.GCM.open(
            sealedBox,
            using: SymmetricKey(data: key),
            authenticating: associatedData
        )
    }

    public func rekey(_ key: Data) throws -> Data {
        try derivedRekey(key)
    }
}

private func noiseHKDF(
    chainingKey: Data,
    inputKeyMaterial: Data,
    outputCount: Int,
    hmac: (_ key: Data, _ data: Data) -> Data
) -> [Data] {
    guard outputCount > 0, outputCount <= Int(UInt8.max) else {
        return []
    }

    let tempKey = hmac(chainingKey, inputKeyMaterial)
    var outputs: [Data] = []
    outputs.reserveCapacity(outputCount)

    var previous = Data()
    for counter in 1...outputCount {
        var input = Data()
        input.append(previous)
        input.append(UInt8(counter))
        previous = hmac(tempKey, input)
        outputs.append(previous)
    }
    return outputs
}

public struct SHA256HashAdapter: NoiseHashAdapter {
    public let name: String = "SHA256"
    public let hashLength: Int = 32

    public init() {}

    public func hash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    public func hkdf(chainingKey: Data, inputKeyMaterial: Data, outputCount: Int) -> [Data] {
        noiseHKDF(chainingKey: chainingKey, inputKeyMaterial: inputKeyMaterial, outputCount: outputCount) { key, data in
            Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
        }
    }
}

public struct SHA512HashAdapter: NoiseHashAdapter {
    public let name: String = "SHA512"
    public let hashLength: Int = 64

    public init() {}

    public func hash(_ data: Data) -> Data {
        Data(SHA512.hash(data: data))
    }

    public func hkdf(chainingKey: Data, inputKeyMaterial: Data, outputCount: Int) -> [Data] {
        noiseHKDF(chainingKey: chainingKey, inputKeyMaterial: inputKeyMaterial, outputCount: outputCount) { key, data in
            Data(HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key)))
        }
    }
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
    private var diffieHellmanAdapters: [String: any NoiseDiffieHellmanAdapter]
    private var cipherAdapters: [String: any NoiseCipherAdapter]
    private var hashAdapters: [String: any NoiseHashAdapter]

    public init(catalog: NoiseAdapterCatalog = .empty, registeringBuiltIns: Bool = false) {
        self.catalog = catalog
        diffieHellmanAdapters = [:]
        cipherAdapters = [:]
        hashAdapters = [:]

        if registeringBuiltIns {
            for adapter in Self.builtInDiffieHellmanAdapters {
                diffieHellmanAdapters[adapter.name] = adapter
                if !self.catalog.diffieHellman.contains(adapter.name) {
                    self.catalog.diffieHellman.append(adapter.name)
                }
            }
            for adapter in Self.builtInCipherAdapters {
                cipherAdapters[adapter.name] = adapter
                if !self.catalog.ciphers.contains(adapter.name) {
                    self.catalog.ciphers.append(adapter.name)
                }
            }
            for adapter in Self.builtInHashAdapters {
                hashAdapters[adapter.name] = adapter
                if !self.catalog.hashes.contains(adapter.name) {
                    self.catalog.hashes.append(adapter.name)
                }
            }
        }
    }

    public static func builtIn() -> NoiseCryptoAdapterRegistry {
        NoiseCryptoAdapterRegistry(registeringBuiltIns: true)
    }

    public func register(diffieHellman name: String) {
        if !catalog.diffieHellman.contains(name) {
            catalog.diffieHellman.append(name)
        }
    }

    public func register(cipher name: String) {
        if !catalog.ciphers.contains(name) {
            catalog.ciphers.append(name)
        }
    }

    public func register(hash name: String) {
        if !catalog.hashes.contains(name) {
            catalog.hashes.append(name)
        }
    }

    public func register(diffieHellman adapter: any NoiseDiffieHellmanAdapter) {
        diffieHellmanAdapters[adapter.name] = adapter
        register(diffieHellman: adapter.name)
    }

    public func register(cipher adapter: any NoiseCipherAdapter) {
        cipherAdapters[adapter.name] = adapter
        register(cipher: adapter.name)
    }

    public func register(hash adapter: any NoiseHashAdapter) {
        hashAdapters[adapter.name] = adapter
        register(hash: adapter.name)
    }

    public func diffieHellman(named name: String) -> (any NoiseDiffieHellmanAdapter)? {
        diffieHellmanAdapters[name]
    }

    public func cipher(named name: String) -> (any NoiseCipherAdapter)? {
        cipherAdapters[name]
    }

    public func hash(named name: String) -> (any NoiseHashAdapter)? {
        hashAdapters[name]
    }

    public func makeProvider(for descriptor: NoiseCryptoSuiteDescriptor) throws -> NoiseCryptoProvider {
        guard let diffieHellman = diffieHellmanAdapters[descriptor.diffieHellman] else {
            throw NoiseCryptoAdapterError.unsupportedDiffieHellman(descriptor.diffieHellman)
        }
        guard let cipher = cipherAdapters[descriptor.cipher] else {
            throw NoiseCryptoAdapterError.unsupportedCipher(descriptor.cipher)
        }
        guard let hash = hashAdapters[descriptor.hash] else {
            throw NoiseCryptoAdapterError.unsupportedHash(descriptor.hash)
        }

        return NoiseCryptoProvider(
            diffieHellman: diffieHellman,
            cipher: cipher,
            hash: hash
        )
    }

    public func snapshot() -> NoiseAdapterCatalog {
        catalog
    }

    public func registerBuiltIns() {
        for adapter in Self.builtInDiffieHellmanAdapters {
            register(diffieHellman: adapter)
        }
        for adapter in Self.builtInCipherAdapters {
            register(cipher: adapter)
        }
        for adapter in Self.builtInHashAdapters {
            register(hash: adapter)
        }
    }

    private static let builtInDiffieHellmanAdapters: [any NoiseDiffieHellmanAdapter] = [
        Curve25519DiffieHellmanAdapter(),
    ]
    private static let builtInCipherAdapters: [any NoiseCipherAdapter] = [
        ChaChaPolyCipherAdapter(),
        AESGCMCipherAdapter(),
    ]
    private static let builtInHashAdapters: [any NoiseHashAdapter] = [
        SHA256HashAdapter(),
        SHA512HashAdapter(),
    ]
}

public struct NoiseCryptoAdapterFactory: Sendable {
    public let registry: NoiseCryptoAdapterRegistry

    public init(registry: NoiseCryptoAdapterRegistry = .builtIn()) {
        self.registry = registry
    }

    public func makeProvider(for descriptor: NoiseCryptoSuiteDescriptor) async throws -> NoiseCryptoProvider {
        try await registry.makeProvider(for: descriptor)
    }
}
