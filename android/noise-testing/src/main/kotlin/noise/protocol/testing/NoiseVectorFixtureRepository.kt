package noise.protocol.testing

import noise.protocol.core.HandshakePattern
import java.nio.file.Path

class NoiseVectorFixtureRepository(
    private val fixturesDirectory: Path,
    private val loader: NoiseVectorFixtureLoader = NoiseVectorFixtureLoader()
) {
    @Volatile
    private var cachedCatalog: NoiseVectorFixtureCatalog? = null

    fun catalog(): NoiseVectorFixtureCatalog {
        val existing = cachedCatalog
        if (existing != null) {
            return existing
        }

        return synchronized(this) {
            cachedCatalog ?: loadCatalog().also { cachedCatalog = it }
        }
    }

    fun all(): List<NoiseVectorFixture> = catalog().all()

    fun findById(vectorId: String): NoiseVectorFixture? = catalog().findById(vectorId)

    fun requireById(vectorId: String): NoiseVectorFixture = catalog().requireById(vectorId)

    fun filter(
        pattern: HandshakePattern? = null,
        dh: VectorDhAlgorithm? = null,
        cipher: VectorCipherAlgorithm? = null,
        hash: VectorHashAlgorithm? = null
    ): List<NoiseVectorFixture> {
        return catalog().filter(
            pattern = pattern,
            dh = dh,
            cipher = cipher,
            hash = hash
        )
    }

    private fun loadCatalog(): NoiseVectorFixtureCatalog {
        return NoiseVectorFixtureCatalog(loader.loadAll(fixturesDirectory))
    }
}

class NoiseVectorFixtureCatalog internal constructor(
    fixtures: List<NoiseVectorFixture>
) {
    private val allFixtures: List<NoiseVectorFixture> = fixtures.toList()
    private val fixturesById: Map<String, NoiseVectorFixture> = allFixtures.associateBy { it.vectorId }

    init {
        require(fixturesById.size == allFixtures.size) {
            "Fixture corpus contains duplicate vector_id values."
        }
    }

    fun all(): List<NoiseVectorFixture> = allFixtures

    fun findById(vectorId: String): NoiseVectorFixture? = fixturesById[vectorId]

    fun requireById(vectorId: String): NoiseVectorFixture {
        return findById(vectorId)
            ?: error("Fixture '$vectorId' does not exist in the loaded corpus.")
    }

    fun filter(
        pattern: HandshakePattern? = null,
        dh: VectorDhAlgorithm? = null,
        cipher: VectorCipherAlgorithm? = null,
        hash: VectorHashAlgorithm? = null
    ): List<NoiseVectorFixture> {
        return allFixtures.filter { fixture ->
            (pattern == null || fixture.protocol.pattern == pattern) &&
                (dh == null || fixture.protocol.suite.dh == dh) &&
                (cipher == null || fixture.protocol.suite.cipher == cipher) &&
                (hash == null || fixture.protocol.suite.hash == hash)
        }
    }
}