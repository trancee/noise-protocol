val canonicalVersion = run {
    val versionFile = rootDir.resolve("../VERSION")
    check(versionFile.isFile) {
        "Missing canonical VERSION file at ${versionFile.absolutePath}"
    }
    versionFile.readText().trim().also {
        check(it.isNotEmpty()) { "Canonical VERSION file is empty." }
    }
}

allprojects {
    group = "noise.protocol"
    version = canonicalVersion
}
