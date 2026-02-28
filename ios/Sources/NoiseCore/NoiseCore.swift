import Foundation

public enum NoiseCoreVersion: Sendable {
    public static let specificationRevision = 34
}

public struct NoiseProtocolDescriptor: Sendable, Hashable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public static let bootstrapDefault = NoiseProtocolDescriptor(
        rawValue: "Noise_XX_25519_ChaChaPoly_BLAKE2s"
    )
}

public struct NoiseHandshakeConfiguration: Sendable, Equatable {
    public var protocolName: NoiseProtocolDescriptor
    public var isInitiator: Bool

    public init(
        protocolName: NoiseProtocolDescriptor = .bootstrapDefault,
        isInitiator: Bool
    ) {
        self.protocolName = protocolName
        self.isInitiator = isInitiator
    }
}

public enum NoiseCoreBootstrapError: Error, Sendable, Equatable {
    case notImplemented(String)
}

public actor NoiseHandshakeSession {
    public private(set) var configuration: NoiseHandshakeConfiguration?

    public init() {}

    public func initialize(with configuration: NoiseHandshakeConfiguration) {
        self.configuration = configuration
    }

    public func writeMessage(payload: Data) async throws -> Data {
        _ = payload
        throw NoiseCoreBootstrapError.notImplemented("writeMessage(payload:)")
    }

    public func readMessage(_ message: Data) async throws -> Data {
        _ = message
        throw NoiseCoreBootstrapError.notImplemented("readMessage(_:)")
    }
}
