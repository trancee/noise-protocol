plugins {
    id("org.jetbrains.kotlin.jvm")
    id("com.vanniktech.maven.publish")
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(project(":noise-core"))

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}

mavenPublishing {
    publishToMavenCentral()
    val signingInMemoryKey = providers.gradleProperty("signingInMemoryKey").orNull
    val signingInMemoryKeyPassword = providers.gradleProperty("signingInMemoryKeyPassword").orNull
    val signingKeyId = providers.gradleProperty("signing.keyId").orNull
    val signingPassword = providers.gradleProperty("signing.password").orNull
    val signingSecretKeyRingFile = providers.gradleProperty("signing.secretKeyRingFile").orNull
    val hasSigningConfiguration =
        (
            !signingInMemoryKey.isNullOrBlank() &&
                !signingInMemoryKeyPassword.isNullOrBlank()
            ) ||
            (
                !signingKeyId.isNullOrBlank() &&
                    !signingPassword.isNullOrBlank() &&
                    !signingSecretKeyRingFile.isNullOrBlank()
                )
    if (hasSigningConfiguration) {
        signAllPublications()
    }
    coordinates("ch.trancee", "noise-crypto", version.toString())
    pom {
        name.set("Noise Protocol Crypto Adapters")
        description.set("Crypto adapter implementations for Noise Protocol core.")
        url.set("https://github.com/trancee/noise-protocol")
        licenses {
            license {
                name.set("Unlicense")
                url.set("https://unlicense.org/")
            }
        }
        developers {
            developer {
                id.set("trancee")
                name.set("trancee")
                url.set("https://github.com/trancee")
            }
        }
        scm {
            url.set("https://github.com/trancee/noise-protocol")
            connection.set("scm:git:git://github.com/trancee/noise-protocol.git")
            developerConnection.set("scm:git:ssh://git@github.com/trancee/noise-protocol.git")
        }
    }
}
