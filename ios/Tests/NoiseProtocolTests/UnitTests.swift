import XCTest
@testable import NoiseProtocol
import Foundation

// MARK: - CipherState Tests

final class CipherStateTests: XCTestCase {

    func testNoKeyPassthrough() throws {
        let cs = CipherState()
        let plaintext = Data("hello".utf8)
        let ad = Data("ad".utf8)
        let result = try cs.encryptWithAd(ad, plaintext: plaintext)
        XCTAssertEqual(result, plaintext, "Without key, encryptWithAd should return plaintext")

        let decrypted = try cs.decryptWithAd(ad, ciphertext: plaintext)
        XCTAssertEqual(decrypted, plaintext, "Without key, decryptWithAd should return ciphertext")
    }

    func testEncryptDecryptRoundTrip() throws {
        let cs = CipherState()
        let key = Data(repeating: 0x42, count: 32)
        cs.initializeKey(key)
        XCTAssertTrue(cs.hasKey)

        let ad = Data("associated data".utf8)
        let plaintext = Data("secret message".utf8)

        let ciphertext = try cs.encryptWithAd(ad, plaintext: plaintext)
        XCTAssertNotEqual(ciphertext, plaintext)
        XCTAssertEqual(ciphertext.count, plaintext.count + 16) // 16-byte AEAD tag

        // New CipherState for decryption (same key, nonce resets to 0)
        let cs2 = CipherState()
        cs2.initializeKey(key)
        let decrypted = try cs2.decryptWithAd(ad, ciphertext: ciphertext)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testNonceIncrement() throws {
        let cs = CipherState()
        cs.initializeKey(Data(repeating: 0x01, count: 32))
        XCTAssertEqual(cs.getNonce(), 0)

        _ = try cs.encryptWithAd(Data(), plaintext: Data("a".utf8))
        XCTAssertEqual(cs.getNonce(), 1)

        _ = try cs.encryptWithAd(Data(), plaintext: Data("b".utf8))
        XCTAssertEqual(cs.getNonce(), 2)
    }

    func testDecryptionFailureDoesNotIncrementNonce() throws {
        let cs = CipherState()
        cs.initializeKey(Data(repeating: 0x01, count: 32))

        let badCiphertext = Data(repeating: 0xFF, count: 32)
        XCTAssertThrowsError(try cs.decryptWithAd(Data(), ciphertext: badCiphertext))
        XCTAssertEqual(cs.getNonce(), 0, "Nonce should not increment after decryption failure")
    }

    func testRekey() throws {
        let cs = CipherState()
        let key = Data(repeating: 0xAB, count: 32)
        cs.initializeKey(key)

        let plaintext = Data("test".utf8)
        let ct1 = try cs.encryptWithAd(Data(), plaintext: plaintext)

        // Rekey and encrypt again — should produce different ciphertext
        try cs.rekey()
        cs.setNonce(0)
        let ct2 = try cs.encryptWithAd(Data(), plaintext: plaintext)
        XCTAssertNotEqual(ct1, ct2, "Rekey should change the cipher key")
    }

    func testRekeyWithoutKeyThrows() {
        let cs = CipherState()
        XCTAssertThrowsError(try cs.rekey())
    }
}

// MARK: - Handshake Round-Trip Tests (random keys)

final class HandshakeRoundTripTests: XCTestCase {

    func testNNRoundTrip() throws {
        let initiator = HandshakeState(pattern: .NN, initiator: true)
        let responder = HandshakeState(pattern: .NN, initiator: false)

        // Message 1: initiator → responder
        let (msg1, _) = try initiator.writeMessage(payload: Data("hello".utf8))
        let (payload1, _) = try responder.readMessage(msg1)
        XCTAssertEqual(String(data: payload1, encoding: .utf8), "hello")

        // Message 2: responder → initiator
        let (msg2, respTransport) = try responder.writeMessage(payload: Data("world".utf8))
        let (payload2, initTransport) = try initiator.readMessage(msg2)
        XCTAssertEqual(String(data: payload2, encoding: .utf8), "world")

        XCTAssertNotNil(initTransport)
        XCTAssertNotNil(respTransport)

        // Transport round-trip
        let secret = Data("transport data".utf8)
        let ct = try initTransport!.sendCipher.encryptWithAd(Data(), plaintext: secret)
        let pt = try respTransport!.receiveCipher.decryptWithAd(Data(), ciphertext: ct)
        XCTAssertEqual(pt, secret)
    }

    func testXXRoundTrip() throws {
        let initS = NoiseKeyPair()
        let respS = NoiseKeyPair()

        let initiator = HandshakeState(
            pattern: .XX, initiator: true,
            s: initS
        )
        let responder = HandshakeState(
            pattern: .XX, initiator: false,
            s: respS
        )

        // Message 1: initiator → responder
        let (msg1, _) = try initiator.writeMessage()
        let (_, _) = try responder.readMessage(msg1)

        // Message 2: responder → initiator
        let (msg2, _) = try responder.writeMessage()
        let (_, _) = try initiator.readMessage(msg2)

        // Message 3: initiator → responder
        let (msg3, initT) = try initiator.writeMessage(payload: Data("done".utf8))
        let (p3, respT) = try responder.readMessage(msg3)

        XCTAssertEqual(String(data: p3, encoding: .utf8), "done")
        XCTAssertNotNil(initT)
        XCTAssertNotNil(respT)

        // Both sides should agree on handshake hash
        XCTAssertEqual(initT!.handshakeHash, respT!.handshakeHash)

        // Both sides should know each other's static keys
        XCTAssertEqual(initT!.remoteStaticKey, respS.publicKey)
        XCTAssertEqual(respT!.remoteStaticKey, initS.publicKey)
    }

    func testIKRoundTrip() throws {
        let initS = NoiseKeyPair()
        let respS = NoiseKeyPair()

        let initiator = HandshakeState(
            pattern: .IK, initiator: true,
            s: initS,
            rs: respS.publicKey
        )
        let responder = HandshakeState(
            pattern: .IK, initiator: false,
            s: respS,
            rs: initS.publicKey
        )

        let (msg1, _) = try initiator.writeMessage(payload: Data("ik-hello".utf8))
        let (p1, _) = try responder.readMessage(msg1)
        XCTAssertEqual(String(data: p1, encoding: .utf8), "ik-hello")

        let (msg2, respT) = try responder.writeMessage()
        let (_, initT) = try initiator.readMessage(msg2)

        XCTAssertNotNil(initT)
        XCTAssertNotNil(respT)
        XCTAssertEqual(initT!.handshakeHash, respT!.handshakeHash)
    }

    func testNKRoundTrip() throws {
        let respS = NoiseKeyPair()

        let initiator = HandshakeState(
            pattern: .NK, initiator: true,
            rs: respS.publicKey
        )
        let responder = HandshakeState(
            pattern: .NK, initiator: false,
            s: respS
        )

        let (msg1, _) = try initiator.writeMessage()
        let (_, _) = try responder.readMessage(msg1)

        let (msg2, respT) = try responder.writeMessage()
        let (_, initT) = try initiator.readMessage(msg2)

        XCTAssertNotNil(initT)
        XCTAssertNotNil(respT)
        XCTAssertEqual(initT!.handshakeHash, respT!.handshakeHash)
    }

    func testEmptyPayloads() throws {
        let initiator = HandshakeState(pattern: .NN, initiator: true)
        let responder = HandshakeState(pattern: .NN, initiator: false)

        let (msg1, _) = try initiator.writeMessage()
        let (p1, _) = try responder.readMessage(msg1)
        XCTAssertTrue(p1.isEmpty)

        let (msg2, _) = try responder.writeMessage()
        let (p2, _) = try initiator.readMessage(msg2)
        XCTAssertTrue(p2.isEmpty)
    }
}

// MARK: - Error Handling Tests

final class ErrorHandlingTests: XCTestCase {

    func testHandshakeAlreadyComplete() throws {
        let initiator = HandshakeState(pattern: .NN, initiator: true)
        let responder = HandshakeState(pattern: .NN, initiator: false)

        let (msg1, _) = try initiator.writeMessage()
        let (_, _) = try responder.readMessage(msg1)
        let (msg2, _) = try responder.writeMessage()
        let (_, _) = try initiator.readMessage(msg2)

        // Should throw on further writes
        XCTAssertThrowsError(try initiator.writeMessage()) { error in
            guard case NoiseError.handshakeAlreadyComplete = error else {
                XCTFail("Expected handshakeAlreadyComplete, got \(error)")
                return
            }
        }
    }

    func testDecryptionFailureWithWrongKey() throws {
        let cs = CipherState()
        cs.initializeKey(Data(repeating: 0x01, count: 32))
        let ct = try cs.encryptWithAd(Data(), plaintext: Data("test".utf8))

        let cs2 = CipherState()
        cs2.initializeKey(Data(repeating: 0x02, count: 32))
        XCTAssertThrowsError(try cs2.decryptWithAd(Data(), ciphertext: ct)) { error in
            guard case NoiseError.decryptionFailed = error else {
                XCTFail("Expected decryptionFailed, got \(error)")
                return
            }
        }
    }

    func testWrongADDecryptionFails() throws {
        let key = Data(repeating: 0x42, count: 32)
        let cs1 = CipherState()
        cs1.initializeKey(key)
        let ct = try cs1.encryptWithAd(Data("ad1".utf8), plaintext: Data("test".utf8))

        let cs2 = CipherState()
        cs2.initializeKey(key)
        XCTAssertThrowsError(try cs2.decryptWithAd(Data("wrong-ad".utf8), ciphertext: ct))
    }
}

// MARK: - DH Tests

final class DHTests: XCTestCase {

    func testKeyPairGeneration() {
        let kp = NoiseKeyPair()
        XCTAssertEqual(kp.publicKey.count, DHLEN)
    }

    func testDeterministicKeyPair() throws {
        let priv = Data(hex: "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
        let kp = try NoiseKeyPair(privateKeyData: priv)
        let expectedPub = Data(hex: "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
        XCTAssertEqual(kp.publicKey.hex, expectedPub.hex)
    }

    func testDHSymmetry() throws {
        let alice = NoiseKeyPair()
        let bob = NoiseKeyPair()

        let shared1 = try alice.dh(remotePublicKey: bob.publicKey)
        let shared2 = try bob.dh(remotePublicKey: alice.publicKey)
        XCTAssertEqual(shared1, shared2, "DH should be symmetric")
    }

    func testDHOutputLength() throws {
        let alice = NoiseKeyPair()
        let bob = NoiseKeyPair()
        let shared = try alice.dh(remotePublicKey: bob.publicKey)
        XCTAssertEqual(shared.count, DHLEN)
    }
}

// MARK: - Pattern Tests

final class PatternTests: XCTestCase {

    func testPatternLookup() {
        XCTAssertNotNil(HandshakePattern.all["NN"])
        XCTAssertNotNil(HandshakePattern.all["NK"])
        XCTAssertNotNil(HandshakePattern.all["XX"])
        XCTAssertNotNil(HandshakePattern.all["IK"])
        XCTAssertNotNil(HandshakePattern.all["XXfallback"])
        XCTAssertNotNil(HandshakePattern.all["NKpsk0"])
        XCTAssertNotNil(HandshakePattern.all["IKpsk2"])
    }

    func testOneWayPatterns() {
        XCTAssertNotNil(HandshakePattern.all["N"])
        XCTAssertNotNil(HandshakePattern.all["K"])
        XCTAssertNotNil(HandshakePattern.all["X"])
    }

    func testDeferredPatterns() {
        let deferred = ["NK1", "NX1", "X1N", "X1K", "XK1", "X1K1", "X1X", "XX1", "X1X1",
                        "K1N", "K1K", "KK1", "K1K1", "K1X", "KX1", "K1X1",
                        "I1N", "I1K", "IK1", "I1K1", "I1X", "IX1", "I1X1"]
        for name in deferred {
            XCTAssertNotNil(HandshakePattern.all[name], "Missing deferred pattern: \(name)")
        }
    }

    func testWithPSKModifier() {
        let nk = HandshakePattern.NK
        let nkpsk0 = nk.withPSK(positions: [0])
        XCTAssertEqual(nkpsk0.name, "NKpsk0")
        XCTAssertEqual(nkpsk0.messagePatterns[0].first, .psk)
    }

    func testXXfallbackDefinition() {
        let p = HandshakePattern.XXfallback
        XCTAssertEqual(p.name, "XXfallback")
        XCTAssertTrue(p.responderPreMessage.contains(.e))
        XCTAssertTrue(p.initiatorPreMessage.isEmpty)
        XCTAssertEqual(p.messagePatterns.count, 2)
    }

    func testNKpsk0Definition() {
        let p = HandshakePattern.NKpsk0
        XCTAssertEqual(p.messagePatterns[0], [.psk, .e, .es])
        XCTAssertEqual(p.messagePatterns[1], [.e, .ee])
        XCTAssertEqual(p.responderPreMessage, [.s])
    }

    func testIKpsk2Definition() {
        let p = HandshakePattern.IKpsk2
        XCTAssertEqual(p.messagePatterns[0], [.e, .es, .s, .ss])
        XCTAssertEqual(p.messagePatterns[1], [.e, .ee, .se, .psk])
        XCTAssertEqual(p.responderPreMessage, [.s])
    }
}

// MARK: - Channel Binding Tests

final class ChannelBindingTests: XCTestCase {

    func testHandshakeHashMatch() throws {
        let initS = NoiseKeyPair()
        let respS = NoiseKeyPair()

        let initiator = HandshakeState(
            pattern: .XX, initiator: true,
            prologue: Data("test-prologue".utf8),
            s: initS
        )
        let responder = HandshakeState(
            pattern: .XX, initiator: false,
            prologue: Data("test-prologue".utf8),
            s: respS
        )

        let (m1, _) = try initiator.writeMessage()
        let (_, _) = try responder.readMessage(m1)
        let (m2, _) = try responder.writeMessage()
        let (_, _) = try initiator.readMessage(m2)
        let (m3, iT) = try initiator.writeMessage()
        let (_, rT) = try responder.readMessage(m3)

        XCTAssertEqual(iT!.handshakeHash, rT!.handshakeHash)
        // Hash should be 32 bytes
        XCTAssertEqual(iT!.handshakeHash.count, 32)
    }

    func testDifferentPrologueProducesDifferentHash() throws {
        func doHandshake(prologue: Data) throws -> Data {
            let initiator = HandshakeState(pattern: .NN, initiator: true, prologue: prologue)
            let responder = HandshakeState(pattern: .NN, initiator: false, prologue: prologue)
            let (m1, _) = try initiator.writeMessage()
            let (_, _) = try responder.readMessage(m1)
            let (m2, _) = try responder.writeMessage()
            let (_, t) = try initiator.readMessage(m2)
            return t!.handshakeHash
        }

        let h1 = try doHandshake(prologue: Data("prologue-A".utf8))
        let h2 = try doHandshake(prologue: Data("prologue-B".utf8))
        XCTAssertNotEqual(h1, h2)
    }
}
