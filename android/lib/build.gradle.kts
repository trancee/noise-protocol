plugins {
    kotlin("jvm")
    `java-library`
    id("com.vanniktech.maven.publish")
}

base {
    archivesName.set("noise-protocol")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation("ch.trancee:blake-hash:1.1.1")
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.14.3")
    testImplementation("org.json:json:20240303")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        showStandardStreams = true
    }
}

sourceSets {
    test {
        resources {
            srcDir(rootProject.file("../test-vectors"))
        }
    }
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()
    coordinates("ch.trancee", "noise-protocol", version.toString())

    pom {
        name.set("Noise Protocol")
        description.set("Noise Protocol Framework implementation for Kotlin/JVM")
        url.set("https://github.com/trancee/noise-protocol")
        inceptionYear.set("2026")
        licenses {
            license {
                name.set("The Unlicense")
                url.set("https://unlicense.org")
            }
        }
        developers {
            developer {
                id.set("trancee")
                name.set("trancee")
                url.set("https://github.com/trancee/noise-protocol")
            }
        }
        scm {
            url.set("https://github.com/trancee/noise-protocol")
            connection.set("scm:git:git://github.com/trancee/noise-protocol.git")
            developerConnection.set("scm:git:ssh://git@github.com/trancee/noise-protocol.git")
        }
    }
}
