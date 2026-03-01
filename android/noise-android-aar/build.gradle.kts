import org.gradle.api.publish.maven.MavenPublication
import org.gradle.jvm.tasks.Jar

plugins {
    id("com.android.library")
    `maven-publish`
    signing
}

android {
    namespace = "noise.protocol.android.aar"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":noise-core"))
    api(project(":noise-crypto"))
}

val docsJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    from(rootProject.file("../README.md"))
}

publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "noise-android-aar"
            pom {
                name.set("Noise Protocol Android AAR")
                description.set("Android AAR wrapper for noise-core and noise-crypto modules.")
            }
            artifact(docsJar)
        }
    }
    repositories {
        val githubPackagesUrl = providers.environmentVariable("GITHUB_PACKAGES_URL").orNull
            ?: providers.environmentVariable("GITHUB_REPOSITORY").orNull?.let {
                "https://maven.pkg.github.com/$it"
            }
        val externalMavenUrl = providers.environmentVariable("MAVEN_REPOSITORY_URL").orNull
        val externalMavenUsername = providers.environmentVariable("MAVEN_REPOSITORY_USERNAME").orNull
            ?: providers.environmentVariable("MAVEN_USERNAME").orNull
        val externalMavenPassword = providers.environmentVariable("MAVEN_REPOSITORY_PASSWORD").orNull
            ?: providers.environmentVariable("MAVEN_PASSWORD").orNull

        if (!githubPackagesUrl.isNullOrBlank()) {
            maven {
                name = "GitHubPackages"
                url = uri(githubPackagesUrl)
                credentials {
                    username = providers.environmentVariable("GITHUB_ACTOR").orNull
                    password = providers.environmentVariable("GITHUB_TOKEN").orNull
                }
            }
        }

        if (!externalMavenUrl.isNullOrBlank()) {
            maven {
                name = "ExternalMaven"
                url = uri(externalMavenUrl)
                credentials {
                    username = externalMavenUsername
                    password = externalMavenPassword
                }
            }
        }
    }
}

afterEvaluate {
    publishing.publications.named("release", MavenPublication::class.java) {
        from(components["release"])
    }
}

signing {
    val signingKeyId = providers.gradleProperty("signingKeyId").orNull
    val signingKey = providers.gradleProperty("signingKey").orNull
    val signingPassword = providers.gradleProperty("signingPassword").orNull

    isRequired = false
    if (!signingKey.isNullOrBlank() && !signingPassword.isNullOrBlank()) {
        useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
        sign(publishing.publications)
    }
}
