import Foundation
import NoiseCore
import Testing
@testable import NoiseCryptoAdapters

@Test("AEAD adapters round-trip and fail on tamper")
func aeadRoundTripAndTamperFailure() throws {
    let key = Data((0..<32).map(UInt8.init))
    let associatedData = Data("noise-ad".utf8)
    let plaintext = Data("noise-payload".utf8)
    let adapters: [any NoiseCipherAdapter] = [
        ChaChaPolyCipherAdapter(),
        AESGCMCipherAdapter(),
    ]

    for adapter in adapters {
        let ciphertext = try adapter.encrypt(
            key: key,
            nonce: 7,
            associatedData: associatedData,
            plaintext: plaintext
        )
        let decrypted = try adapter.decrypt(
            key: key,
            nonce: 7,
            associatedData: associatedData,
            ciphertext: ciphertext
        )
        #expect(decrypted == plaintext)

        var tampered = ciphertext
        let tamperIndex = tampered.index(before: tampered.endIndex)
        tampered[tamperIndex] ^= 0x01

        do {
            _ = try adapter.decrypt(
                key: key,
                nonce: 7,
                associatedData: associatedData,
                ciphertext: tampered
            )
            Issue.record("Expected tamper detection for \(adapter.name).")
        } catch {}
    }
}

@Test("HKDF output is deterministic with expected count and digest sizes")
func hkdfDeterministicOutputCountAndSize() {
    let chainingKey = Data("chain-key".utf8)
    let inputKeyMaterial = Data("input-key-material".utf8)
    let adapters: [any NoiseHashAdapter] = [
        SHA256HashAdapter(),
        SHA512HashAdapter(),
    ]

    for adapter in adapters {
        let firstRun = adapter.hkdf(
            chainingKey: chainingKey,
            inputKeyMaterial: inputKeyMaterial,
            outputCount: 3
        )
        let secondRun = adapter.hkdf(
            chainingKey: chainingKey,
            inputKeyMaterial: inputKeyMaterial,
            outputCount: 3
        )

        #expect(firstRun.count == 3)
        #expect(firstRun == secondRun)
        for output in firstRun {
            #expect(output.count == adapter.hashLength)
        }
    }
}

@Test("Curve25519 DH shared secret is symmetric")
func diffieHellmanSharedSecretSymmetry() throws {
    let adapter = Curve25519DiffieHellmanAdapter()
    let alice = try adapter.generateKeyPair()
    let bob = try adapter.generateKeyPair()

    let aliceSecret = try adapter.dh(privateKey: alice.privateKey, publicKey: bob.publicKey)
    let bobSecret = try adapter.dh(privateKey: bob.privateKey, publicKey: alice.publicKey)

    #expect(aliceSecret == bobSecret)
    #expect(aliceSecret.count == 32)
}

@Test("Registry and factory resolve providers by algorithm names")
func registryAndFactoryWiring() async throws {
    let registry = NoiseCryptoAdapterRegistry(registeringBuiltIns: true)
    let snapshot = await registry.snapshot()

    #expect(snapshot.diffieHellman.contains("25519"))
    #expect(snapshot.ciphers.contains("ChaChaPoly"))
    #expect(snapshot.ciphers.contains("AESGCM"))
    #expect(snapshot.hashes.contains("SHA256"))
    #expect(snapshot.hashes.contains("SHA512"))

    let factory = NoiseCryptoAdapterFactory(registry: registry)
    let suites = [
        NoiseCryptoSuiteDescriptor(
            protocolName: .bootstrapDefault,
            diffieHellman: "25519",
            cipher: "ChaChaPoly",
            hash: "SHA256"
        ),
        NoiseCryptoSuiteDescriptor(
            protocolName: .bootstrapDefault,
            diffieHellman: "25519",
            cipher: "AESGCM",
            hash: "SHA512"
        ),
    ]

    for suite in suites {
        let provider = try await factory.makeProvider(for: suite)
        let keyPair = try provider.diffieHellman.generateKeyPair()
        #expect(keyPair.privateKey.count == 32)
        #expect(keyPair.publicKey.count == 32)
    }

    do {
        _ = try await factory.makeProvider(
            for: NoiseCryptoSuiteDescriptor(
                protocolName: .bootstrapDefault,
                diffieHellman: "25519",
                cipher: "UnknownCipher",
                hash: "SHA256"
            )
        )
        Issue.record("Expected unsupported cipher lookup failure.")
    } catch let error as NoiseCryptoAdapterError {
        #expect(error == .unsupportedCipher("UnknownCipher"))
    }
}
