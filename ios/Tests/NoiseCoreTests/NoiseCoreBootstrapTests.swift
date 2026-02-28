import Testing
@testable import NoiseCore

@Test("Core bootstrap exposes default protocol profile")
func bootstrapDefaultProtocolProfile() {
    #expect(NoiseCoreVersion.specificationRevision == 34)
    #expect(NoiseProtocolDescriptor.bootstrapDefault.rawValue == "Noise_XX_25519_ChaChaPoly_BLAKE2s")
}
