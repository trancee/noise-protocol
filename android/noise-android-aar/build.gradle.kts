plugins {
    id("com.android.library")
    id("com.vanniktech.maven.publish") version "0.36.0"
}

android {
    namespace = "noise.protocol.android.aar"
    compileSdk = 35
    defaultConfig { minSdk = 26 }
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = true) // auto publish after validation
    signAllPublications()

    coordinates("ch.trancee", "noise-android-aar", version.toString())

    pom {
        name.set("Noise Protocol Android AAR")
        description.set("Android AAR wrapper for noise-core and noise-crypto modules.")
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
