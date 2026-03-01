import org.gradle.util.GradleVersion

pluginManagement {
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "com.android.library") {
                val agpVersion = if (GradleVersion.current() >= GradleVersion.version("9.0")) {
                    "9.0.1"
                } else {
                    "8.8.2"
                }
                useModule("com.android.tools.build:gradle:$agpVersion")
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
