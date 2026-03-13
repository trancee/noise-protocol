import Foundation

/// Token types in a Noise handshake message pattern.
public enum Token: String, Sendable {
    case e, s, ee, es, se, ss, psk
}

/// A message pattern is a sequence of tokens processed in one direction.
public typealias MessagePattern = [Token]

/// Defines a Noise handshake pattern with pre-messages and message patterns.
public struct HandshakePattern: Sendable {
    public let name: String
    /// Pre-message tokens for the initiator (e.g., `[.s]` for K-type patterns).
    public let initiatorPreMessage: [Token]
    /// Pre-message tokens for the responder (e.g., `[.s]` for NK, XK, IK patterns).
    public let responderPreMessage: [Token]
    /// Sequence of message patterns, alternating initiator→responder.
    public let messagePatterns: [MessagePattern]

    public init(
        name: String,
        initiatorPreMessage: [Token] = [],
        responderPreMessage: [Token] = [],
        messagePatterns: [MessagePattern]
    ) {
        self.name = name
        self.initiatorPreMessage = initiatorPreMessage
        self.responderPreMessage = responderPreMessage
        self.messagePatterns = messagePatterns
    }
}

// MARK: - One-way patterns

extension HandshakePattern {
    public static let N = HandshakePattern(
        name: "N",
        responderPreMessage: [.s],
        messagePatterns: [[.e, .es]]
    )

    public static let K = HandshakePattern(
        name: "K",
        initiatorPreMessage: [.s],
        responderPreMessage: [.s],
        messagePatterns: [[.e, .es, .ss]]
    )

    public static let X = HandshakePattern(
        name: "X",
        responderPreMessage: [.s],
        messagePatterns: [[.e, .es, .s, .ss]]
    )
}

// MARK: - Fundamental interactive patterns

extension HandshakePattern {
    public static let NN = HandshakePattern(
        name: "NN",
        messagePatterns: [
            [.e],
            [.e, .ee]
        ]
    )

    public static let NK = HandshakePattern(
        name: "NK",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .es],
            [.e, .ee]
        ]
    )

    public static let NX = HandshakePattern(
        name: "NX",
        messagePatterns: [
            [.e],
            [.e, .ee, .s, .es]
        ]
    )

    public static let XN = HandshakePattern(
        name: "XN",
        messagePatterns: [
            [.e],
            [.e, .ee],
            [.s, .se]
        ]
    )

    public static let XK = HandshakePattern(
        name: "XK",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .es],
            [.e, .ee],
            [.s, .se]
        ]
    )

    public static let XX = HandshakePattern(
        name: "XX",
        messagePatterns: [
            [.e],
            [.e, .ee, .s, .es],
            [.s, .se]
        ]
    )

    public static let KN = HandshakePattern(
        name: "KN",
        initiatorPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .se]
        ]
    )

    public static let KK = HandshakePattern(
        name: "KK",
        initiatorPreMessage: [.s],
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .es, .ss],
            [.e, .ee, .se]
        ]
    )

    public static let KX = HandshakePattern(
        name: "KX",
        initiatorPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .se, .s, .es]
        ]
    )

    public static let IN = HandshakePattern(
        name: "IN",
        messagePatterns: [
            [.e, .s],
            [.e, .ee, .se]
        ]
    )

    public static let IK = HandshakePattern(
        name: "IK",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .es, .s, .ss],
            [.e, .ee, .se]
        ]
    )

    public static let IX = HandshakePattern(
        name: "IX",
        messagePatterns: [
            [.e, .s],
            [.e, .ee, .se, .s, .es]
        ]
    )
}

// MARK: - Deferred patterns

extension HandshakePattern {
    public static let NK1 = HandshakePattern(
        name: "NK1",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .es]
        ]
    )

    public static let NX1 = HandshakePattern(
        name: "NX1",
        messagePatterns: [
            [.e],
            [.e, .ee, .s],
            [.es]
        ]
    )

    public static let X1N = HandshakePattern(
        name: "X1N",
        messagePatterns: [
            [.e],
            [.e, .ee],
            [.s],
            [.se]
        ]
    )

    public static let X1K = HandshakePattern(
        name: "X1K",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .es],
            [.e, .ee],
            [.s],
            [.se]
        ]
    )

    public static let XK1 = HandshakePattern(
        name: "XK1",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .es],
            [.s, .se]
        ]
    )

    public static let X1K1 = HandshakePattern(
        name: "X1K1",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .es],
            [.s],
            [.se]
        ]
    )

    public static let X1X = HandshakePattern(
        name: "X1X",
        messagePatterns: [
            [.e],
            [.e, .ee, .s, .es],
            [.s],
            [.se]
        ]
    )

    public static let XX1 = HandshakePattern(
        name: "XX1",
        messagePatterns: [
            [.e],
            [.e, .ee, .s],
            [.es, .s, .se]
        ]
    )

    public static let X1X1 = HandshakePattern(
        name: "X1X1",
        messagePatterns: [
            [.e],
            [.e, .ee, .s],
            [.es, .s],
            [.se]
        ]
    )

    public static let K1N = HandshakePattern(
        name: "K1N",
        initiatorPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee],
            [.se]
        ]
    )

    public static let K1K = HandshakePattern(
        name: "K1K",
        initiatorPreMessage: [.s],
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .es],
            [.e, .ee],
            [.se]
        ]
    )

    public static let KK1 = HandshakePattern(
        name: "KK1",
        initiatorPreMessage: [.s],
        responderPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .se, .es]
        ]
    )

    public static let K1K1 = HandshakePattern(
        name: "K1K1",
        initiatorPreMessage: [.s],
        responderPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .es],
            [.se]
        ]
    )

    public static let K1X = HandshakePattern(
        name: "K1X",
        initiatorPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .s, .es],
            [.se]
        ]
    )

    public static let KX1 = HandshakePattern(
        name: "KX1",
        initiatorPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .se, .s],
            [.es]
        ]
    )

    public static let K1X1 = HandshakePattern(
        name: "K1X1",
        initiatorPreMessage: [.s],
        messagePatterns: [
            [.e],
            [.e, .ee, .s],
            [.se, .es]
        ]
    )

    public static let I1N = HandshakePattern(
        name: "I1N",
        messagePatterns: [
            [.e, .s],
            [.e, .ee],
            [.se]
        ]
    )

    public static let I1K = HandshakePattern(
        name: "I1K",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .es, .s],
            [.e, .ee],
            [.se]
        ]
    )

    public static let IK1 = HandshakePattern(
        name: "IK1",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .s],
            [.e, .ee, .se, .es]
        ]
    )

    public static let I1K1 = HandshakePattern(
        name: "I1K1",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .s],
            [.e, .ee, .es],
            [.se]
        ]
    )

    public static let I1X = HandshakePattern(
        name: "I1X",
        messagePatterns: [
            [.e, .s],
            [.e, .ee, .s, .es],
            [.se]
        ]
    )

    public static let IX1 = HandshakePattern(
        name: "IX1",
        messagePatterns: [
            [.e, .s],
            [.e, .ee, .se, .s],
            [.es]
        ]
    )

    public static let I1X1 = HandshakePattern(
        name: "I1X1",
        messagePatterns: [
            [.e, .s],
            [.e, .ee, .s],
            [.se, .es]
        ]
    )
}

// MARK: - Fallback pattern

extension HandshakePattern {
    /// XXfallback: roles are reversed from original XX.
    /// The fallback initiator (original responder) sends first.
    /// The responder's pre-message `e` is the original initiator's ephemeral.
    /// DH tokens es/se are swapped to account for role reversal.
    public static let XXfallback = HandshakePattern(
        name: "XXfallback",
        responderPreMessage: [.e],
        messagePatterns: [
            [.e, .ee, .s, .se],
            [.s, .es]
        ]
    )
}

// MARK: - Named PSK patterns

extension HandshakePattern {
    public static let NKpsk0 = HandshakePattern(
        name: "NKpsk0",
        responderPreMessage: [.s],
        messagePatterns: [
            [.psk, .e, .es],
            [.e, .ee]
        ]
    )

    /// IKpsk2 (WireGuard-style): IK with PSK at end of second handshake message.
    public static let IKpsk2 = HandshakePattern(
        name: "IKpsk2",
        responderPreMessage: [.s],
        messagePatterns: [
            [.e, .es, .s, .ss],
            [.e, .ee, .se, .psk]
        ]
    )
}

// MARK: - PSK modifier

extension HandshakePattern {
    /// Apply PSK modifiers to a base pattern.
    /// `positions` indicates where psk tokens are placed:
    /// - 0: beginning of first message
    /// - N (1..): end of Nth message
    public func withPSK(positions: [Int]) -> HandshakePattern {
        var modified = messagePatterns
        for pos in positions.sorted() {
            if pos == 0 {
                modified[0].insert(.psk, at: 0)
            } else {
                let msgIndex = pos - 1
                if msgIndex < modified.count {
                    modified[msgIndex].append(.psk)
                }
            }
        }
        let pskSuffix = positions.map { "psk\($0)" }.joined(separator: "+")
        return HandshakePattern(
            name: "\(name)\(pskSuffix)",
            initiatorPreMessage: initiatorPreMessage,
            responderPreMessage: responderPreMessage,
            messagePatterns: modified
        )
    }
}

// MARK: - Lookup

extension HandshakePattern {
    /// All named fundamental and deferred patterns.
    public static let all: [String: HandshakePattern] = [
        "N": .N, "K": .K, "X": .X,
        "NN": .NN, "NK": .NK, "NX": .NX,
        "XN": .XN, "XK": .XK, "XX": .XX,
        "KN": .KN, "KK": .KK, "KX": .KX,
        "IN": .IN, "IK": .IK, "IX": .IX,
        "NK1": .NK1, "NX1": .NX1,
        "X1N": .X1N, "X1K": .X1K, "XK1": .XK1, "X1K1": .X1K1,
        "X1X": .X1X, "XX1": .XX1, "X1X1": .X1X1,
        "K1N": .K1N, "K1K": .K1K, "KK1": .KK1, "K1K1": .K1K1,
        "K1X": .K1X, "KX1": .KX1, "K1X1": .K1X1,
        "I1N": .I1N, "I1K": .I1K, "IK1": .IK1, "I1K1": .I1K1,
        "I1X": .I1X, "IX1": .IX1, "I1X1": .I1X1,
        "XXfallback": .XXfallback,
        "NKpsk0": .NKpsk0,
        "IKpsk2": .IKpsk2
    ]

    public static func named(_ name: String) throws -> HandshakePattern {
        guard let pattern = all[name] else {
            throw NoiseError.unknownPattern(name)
        }
        return pattern
    }
}
