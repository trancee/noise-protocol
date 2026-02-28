import Foundation
import NoiseCore
import Testing
@testable import NoiseTestHarness

@Test("Vector runner returns placeholder skip result")
func vectorRunnerReturnsBootstrapSkipResult() async {
    let runner = NoiseVectorRunner()
    let vector = NoiseVectorCase(
        name: "bootstrap-vector",
        protocolName: .bootstrapDefault,
        payloads: [Data("ping".utf8)]
    )

    let result = await runner.run(vector)
    #expect(result == .skipped(reason: NoiseVectorRunner.bootstrapSkipReason))
}
