import Foundation
import NoiseCore
import NoiseCryptoAdapters

public struct NoiseVectorCase: Sendable, Equatable {
    public let name: String
    public let protocolName: NoiseProtocolDescriptor
    public let payloads: [Data]

    public init(name: String, protocolName: NoiseProtocolDescriptor, payloads: [Data]) {
        self.name = name
        self.protocolName = protocolName
        self.payloads = payloads
    }
}

public enum NoiseVectorRunResult: Sendable, Equatable {
    case passed
    case skipped(reason: String)
}

public actor NoiseVectorRunner {
    public static let bootstrapSkipReason = "Handshake execution is not implemented in bootstrap."

    public init() {}

    public func run(
        _ vector: NoiseVectorCase,
        using registry: NoiseCryptoAdapterRegistry? = nil
    ) async -> NoiseVectorRunResult {
        _ = vector
        _ = registry
        return .skipped(reason: Self.bootstrapSkipReason)
    }
}
