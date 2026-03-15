import XCTest
@testable import NoiseProtocol
import Foundation

final class BenchmarkTests: XCTestCase {

    private let allSuites: [(String, CipherSuite)] = [
        ("ChaChaPoly_SHA256", .noise_25519_ChaChaPoly_SHA256),
        ("ChaChaPoly_SHA512", .noise_25519_ChaChaPoly_SHA512),
        ("ChaChaPoly_BLAKE2s", .noise_25519_ChaChaPoly_BLAKE2s),
        ("ChaChaPoly_BLAKE2b", .noise_25519_ChaChaPoly_BLAKE2b),
        ("AESGCM_SHA256", .noise_25519_AESGCM_SHA256),
        ("AESGCM_SHA512", .noise_25519_AESGCM_SHA512),
        ("AESGCM_BLAKE2s", .noise_25519_AESGCM_BLAKE2s),
        ("AESGCM_BLAKE2b", .noise_25519_AESGCM_BLAKE2b),
    ]

    private let warmupIterations = 5
    private let measuredIterations = 20
    private let transportIterations = 1000
    private let transportWarmup = 100

    // MARK: - Key Requirement Helpers

    private func initiatorNeedsStaticKey(_ pattern: HandshakePattern) -> Bool {
        if pattern.initiatorPreMessage.contains(.s) { return true }
        for (index, msg) in pattern.messagePatterns.enumerated() where index % 2 == 0 {
            if msg.contains(.s) { return true }
        }
        return false
    }

    private func responderNeedsStaticKey(_ pattern: HandshakePattern) -> Bool {
        if pattern.responderPreMessage.contains(.s) { return true }
        for (index, msg) in pattern.messagePatterns.enumerated() where index % 2 == 1 {
            if msg.contains(.s) { return true }
        }
        return false
    }

    private func initiatorNeedsRemoteStatic(_ pattern: HandshakePattern) -> Bool {
        pattern.responderPreMessage.contains(.s)
    }

    private func responderNeedsRemoteStatic(_ pattern: HandshakePattern) -> Bool {
        pattern.initiatorPreMessage.contains(.s)
    }

    private func patternNeedsPSK(_ pattern: HandshakePattern) -> Bool {
        pattern.name.contains("psk")
    }

    // MARK: - Handshake Helpers

    private func runHandshake(
        _ initiator: HandshakeState,
        _ responder: HandshakeState,
        messages: Int
    ) throws {
        var sender = initiator
        var receiver = responder
        for _ in 0..<messages {
            let (msg, _) = try sender.writeMessage()
            let _ = try receiver.readMessage(msg)
            swap(&sender, &receiver)
        }
    }

    private func createHandshakePair(
        pattern: HandshakePattern,
        suite: CipherSuite
    ) -> (HandshakeState, HandshakeState) {
        let initStatic = initiatorNeedsStaticKey(pattern) ? NoiseKeyPair() : nil
        let respStatic = responderNeedsStaticKey(pattern) ? NoiseKeyPair() : nil
        let psks = patternNeedsPSK(pattern) ? [Data(repeating: 0x42, count: 32)] : []

        let initiator = HandshakeState(
            pattern: pattern,
            initiator: true,
            suite: suite,
            s: initStatic,
            rs: initiatorNeedsRemoteStatic(pattern) ? respStatic?.publicKey : nil,
            psks: psks
        )

        let responder = HandshakeState(
            pattern: pattern,
            initiator: false,
            suite: suite,
            s: respStatic,
            rs: responderNeedsRemoteStatic(pattern) ? initStatic?.publicKey : nil,
            psks: psks
        )

        return (initiator, responder)
    }

    // MARK: - Formatting Helpers

    private func pad(_ string: String, to length: Int) -> String {
        string.padding(toLength: length, withPad: " ", startingAt: 0)
    }

    private func formatNumber(_ value: Double, decimals: Int = 1, width: Int = 12) -> String {
        String(format: "%.\(decimals)f", value).padding(toLength: width, withPad: " ", startingAt: 0)
    }

    // MARK: - Benchmark Tests

    func testHandshakeBenchmark() throws {
        let patterns = HandshakePattern.all
            .filter { $0.key != "XXfallback" }
            .sorted { $0.key < $1.key }

        print("")
        print("=== Handshake Benchmark (\(measuredIterations) iterations, \(warmupIterations) warmup) ===")
        print(
            pad("Suite", to: 34) +
            pad("Pattern", to: 11) +
            pad("Messages", to: 11) +
            pad("Avg (µs)", to: 12) +
            pad("Min (µs)", to: 12) +
            pad("Max (µs)", to: 12)
        )

        for (suiteName, suite) in allSuites {
            for (patternName, pattern) in patterns {
                let messageCount = pattern.messagePatterns.count

                // Warmup
                for _ in 0..<warmupIterations {
                    let (initiator, responder) = createHandshakePair(
                        pattern: pattern, suite: suite
                    )
                    try runHandshake(initiator, responder, messages: messageCount)
                }

                // Measured
                var times: [Double] = []
                for _ in 0..<measuredIterations {
                    let (initiator, responder) = createHandshakePair(
                        pattern: pattern, suite: suite
                    )
                    let start = CFAbsoluteTimeGetCurrent()
                    try runHandshake(initiator, responder, messages: messageCount)
                    let elapsed = (CFAbsoluteTimeGetCurrent() - start) * 1_000_000
                    times.append(elapsed)
                }

                let avg = times.reduce(0, +) / Double(times.count)
                let minTime = times.min()!
                let maxTime = times.max()!

                print(
                    pad(suiteName, to: 34) +
                    pad(patternName, to: 11) +
                    pad(String(messageCount), to: 11) +
                    formatNumber(avg) +
                    formatNumber(minTime) +
                    formatNumber(maxTime)
                )
            }
        }
    }

    func testTransportBenchmark() throws {
        let payload = Data(repeating: 0xAB, count: 1024)

        print("")
        print("=== Transport Benchmark (\(transportIterations) iterations, \(transportWarmup) warmup) ===")
        print(
            pad("Suite", to: 34) +
            pad("Encrypt (µs)", to: 14) +
            pad("Decrypt (µs)", to: 14) +
            pad("Throughput (MB/s)", to: 18)
        )

        for (suiteName, suite) in allSuites {
            // Complete NN handshake to get transport state
            let initiator = HandshakeState(pattern: .NN, initiator: true, suite: suite)
            let responder = HandshakeState(pattern: .NN, initiator: false, suite: suite)

            let (msg1, _) = try initiator.writeMessage()
            let _ = try responder.readMessage(msg1)
            let (msg2, respTransport) = try responder.writeMessage()
            let (_, initTransport) = try initiator.readMessage(msg2)

            guard let sendState = initTransport, let recvState = respTransport else {
                XCTFail("Transport state not established for \(suiteName)")
                continue
            }

            let sendCipher = sendState.sendCipher
            let recvCipher = recvState.receiveCipher

            // Warmup
            for _ in 0..<transportWarmup {
                let ct = try sendCipher.encryptWithAd(Data(), plaintext: payload)
                let _ = try recvCipher.decryptWithAd(Data(), ciphertext: ct)
            }

            // Measured
            var encryptTimes: [Double] = []
            var decryptTimes: [Double] = []

            for _ in 0..<transportIterations {
                let startEnc = CFAbsoluteTimeGetCurrent()
                let ct = try sendCipher.encryptWithAd(Data(), plaintext: payload)
                encryptTimes.append(
                    (CFAbsoluteTimeGetCurrent() - startEnc) * 1_000_000
                )

                let startDec = CFAbsoluteTimeGetCurrent()
                let _ = try recvCipher.decryptWithAd(Data(), ciphertext: ct)
                decryptTimes.append(
                    (CFAbsoluteTimeGetCurrent() - startDec) * 1_000_000
                )
            }

            let avgEncrypt = encryptTimes.reduce(0, +) / Double(encryptTimes.count)
            let avgDecrypt = decryptTimes.reduce(0, +) / Double(decryptTimes.count)
            let totalSeconds = (encryptTimes.reduce(0, +) + decryptTimes.reduce(0, +))
                / 1_000_000
            let totalBytes = Double(payload.count * transportIterations * 2)
            let throughput = totalBytes / totalSeconds / (1024 * 1024)

            print(
                pad(suiteName, to: 34) +
                formatNumber(avgEncrypt, width: 14) +
                formatNumber(avgDecrypt, width: 14) +
                formatNumber(throughput, width: 18)
            )
        }
    }

    func testXXfallbackBenchmark() throws {
        print("")
        print("=== XXfallback Benchmark (\(measuredIterations) iterations, \(warmupIterations) warmup) ===")
        print(
            pad("Suite", to: 34) +
            pad("Messages", to: 11) +
            pad("Avg (µs)", to: 12) +
            pad("Min (µs)", to: 12) +
            pad("Max (µs)", to: 12)
        )

        for (suiteName, suite) in allSuites {
            // Warmup
            for _ in 0..<warmupIterations {
                let initStatic = NoiseKeyPair()
                let respStatic = NoiseKeyPair()
                let initEphemeral = NoiseKeyPair()

                let fallbackInitiator = HandshakeState(
                    pattern: .XXfallback,
                    initiator: true,
                    suite: suite,
                    s: respStatic,
                    re: initEphemeral.publicKey
                )
                let fallbackResponder = HandshakeState(
                    pattern: .XXfallback,
                    initiator: false,
                    suite: suite,
                    s: initStatic,
                    e: initEphemeral
                )

                try runHandshake(fallbackInitiator, fallbackResponder, messages: 2)
            }

            // Measured
            var times: [Double] = []
            for _ in 0..<measuredIterations {
                let initStatic = NoiseKeyPair()
                let respStatic = NoiseKeyPair()
                let initEphemeral = NoiseKeyPair()

                let fallbackInitiator = HandshakeState(
                    pattern: .XXfallback,
                    initiator: true,
                    suite: suite,
                    s: respStatic,
                    re: initEphemeral.publicKey
                )
                let fallbackResponder = HandshakeState(
                    pattern: .XXfallback,
                    initiator: false,
                    suite: suite,
                    s: initStatic,
                    e: initEphemeral
                )

                let start = CFAbsoluteTimeGetCurrent()
                try runHandshake(fallbackInitiator, fallbackResponder, messages: 2)
                let elapsed = (CFAbsoluteTimeGetCurrent() - start) * 1_000_000
                times.append(elapsed)
            }

            let avg = times.reduce(0, +) / Double(times.count)
            let minTime = times.min()!
            let maxTime = times.max()!

            print(
                pad(suiteName, to: 34) +
                pad("2", to: 11) +
                formatNumber(avg) +
                formatNumber(minTime) +
                formatNumber(maxTime)
            )
        }
    }
}
