import Testing
@testable import NoiseCryptoAdapters

@Test("Adapter registry starts empty")
func adapterRegistryStartsEmpty() async {
    let registry = NoiseCryptoAdapterRegistry()
    let snapshot = await registry.snapshot()

    #expect(snapshot == .empty)
}
