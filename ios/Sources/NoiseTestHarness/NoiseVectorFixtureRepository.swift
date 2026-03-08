import Foundation

public actor NoiseVectorFixtureRepository {
    private let loader: NoiseVectorFixtureLoader
    private var cachedCatalog: NoiseVectorFixtureCatalog?

    public init(loader: NoiseVectorFixtureLoader = .init()) {
        self.loader = loader
    }

    public func catalog() throws -> NoiseVectorFixtureCatalog {
        if let cachedCatalog {
            return cachedCatalog
        }

        let catalog = try NoiseVectorFixtureCatalog(fixtures: loader.loadFixtures())
        cachedCatalog = catalog
        return catalog
    }

    public func fixtures() throws -> [NoiseVectorFixture] {
        try catalog().all()
    }

    public func fixture(vectorID: String) throws -> NoiseVectorFixture {
        try catalog().fixture(vectorID: vectorID)
    }

    public func filter(
        pattern: NoiseVectorPattern? = nil,
        diffieHellman: NoiseVectorDiffieHellman? = nil,
        cipher: NoiseVectorCipher? = nil,
        hash: NoiseVectorHash? = nil
    ) throws -> [NoiseVectorFixture] {
        try catalog().filter(
            pattern: pattern,
            diffieHellman: diffieHellman,
            cipher: cipher,
            hash: hash
        )
    }
}

public struct NoiseVectorFixtureCatalog: Sendable, Equatable {
    private let allFixtures: [NoiseVectorFixture]
    private let fixturesByID: [String: NoiseVectorFixture]

    public init(fixtures: [NoiseVectorFixture]) throws {
        let indexed = Dictionary(grouping: fixtures, by: \ .vectorID)
        if let duplicate = indexed.first(where: { $0.value.count > 1 }) {
            throw NoiseTestHarnessError.invalidFixture(
                "Fixture corpus contains duplicate vector_id values: \(duplicate.key)."
            )
        }

        self.allFixtures = fixtures
        self.fixturesByID = indexed.mapValues { $0[0] }
    }

    public func all() -> [NoiseVectorFixture] {
        allFixtures
    }

    public func fixture(vectorID: String) throws -> NoiseVectorFixture {
        guard let fixture = fixturesByID[vectorID] else {
            throw NoiseTestHarnessError.fixtureFileNotFound(vectorID)
        }
        return fixture
    }

    public func filter(
        pattern: NoiseVectorPattern? = nil,
        diffieHellman: NoiseVectorDiffieHellman? = nil,
        cipher: NoiseVectorCipher? = nil,
        hash: NoiseVectorHash? = nil
    ) -> [NoiseVectorFixture] {
        allFixtures.filter { fixture in
            (pattern == nil || fixture.protocolInfo.pattern == pattern) &&
                (diffieHellman == nil || fixture.protocolInfo.suite.dh == diffieHellman) &&
                (cipher == nil || fixture.protocolInfo.suite.cipher == cipher) &&
                (hash == nil || fixture.protocolInfo.suite.hash == hash)
        }
    }
}