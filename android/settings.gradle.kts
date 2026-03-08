import org.gradle.util.GradleVersion

pluginManagement {
    val versionCatalogVersions: Map<String, String> = run {
        val catalogFile = file("gradle/libs.versions.toml")
        check(catalogFile.isFile) {
            "Missing version catalog at ${catalogFile.absolutePath}"
        }

        val versionPattern = Regex("""^([A-Za-z0-9_.-]+)\s*=\s*\"([^\"]+)\"\s*$""")
        var inVersionsBlock = false

        buildMap {
            catalogFile.forEachLine { rawLine ->
                val line = rawLine.substringBefore('#').trim()
                when {
                    line == "[versions]" -> inVersionsBlock = true
                    line.startsWith("[") -> inVersionsBlock = false
                    inVersionsBlock -> {
                        versionPattern.matchEntire(line)?.let { match ->
                            put(match.groupValues[1], match.groupValues[2])
                        }
                    }
                }
            }
        }
    }

    val androidGradlePluginVersion =
        versionCatalogVersions["androidGradlePlugin"]
            ?: error("Missing version 'androidGradlePlugin' in gradle/libs.versions.toml")

    val androidGradlePluginLegacyVersion =
        versionCatalogVersions["androidGradlePluginLegacy"]
            ?: error("Missing version 'androidGradlePluginLegacy' in gradle/libs.versions.toml")

    val mavenPublishPluginVersion =
        versionCatalogVersions["mavenPublish"]
            ?: error("Missing version 'mavenPublish' in gradle/libs.versions.toml")

    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "com.android.library") {
                val agpVersion = if (GradleVersion.current() >= GradleVersion.version("9.0")) {
                    androidGradlePluginVersion
                } else {
                    androidGradlePluginLegacyVersion
                }
                useModule("com.android.tools.build:gradle:$agpVersion")
            } else if (requested.id.id == "com.vanniktech.maven.publish") {
                useModule(
                    "com.vanniktech:gradle-maven-publish-plugin:$mavenPublishPluginVersion"
                )
            }
        }
    }
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "noise-protocol"

include(":noise-core")
include(":noise-crypto")
include(":noise-testing")
include(":noise-protocol")
project(":noise-protocol").projectDir = file("noise-android")
