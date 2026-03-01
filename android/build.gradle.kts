plugins {
    id("com.android.library") apply false
    id("com.vanniktech.maven.publish") version "0.36.0" apply false
}

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
    group = "ch.trancee"
    version = canonicalVersion
}
