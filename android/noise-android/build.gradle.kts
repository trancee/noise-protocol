plugins {
    id("com.android.library")
    id("com.vanniktech.maven.publish")
}

android {
    namespace = "noise.protocol.android.aar"
    compileSdk = 35
    defaultConfig { minSdk = 23 }
}

val noiseCoreJar = project(":noise-core").layout.buildDirectory.file("libs/noise-core-${version}.jar")
val noiseCryptoJar = project(":noise-crypto").layout.buildDirectory.file("libs/noise-crypto-${version}.jar")

tasks.named("preBuild") {
    dependsOn(":noise-core:assemble", ":noise-crypto:assemble")
}

dependencies {
    api(files(noiseCoreJar))
    api(files(noiseCryptoJar))
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = true) // auto publish after validation
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

    coordinates("ch.trancee", "noise-protocol", version.toString())

    pom {
        name.set("Noise Protocol Android")
        description.set("Android AAR distribution bundling Noise Protocol core and crypto APIs.")
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
