plugins {
    kotlin("jvm") version "2.3.20"
    id("com.vanniktech.maven.publish") version "0.36.0" apply false
}

allprojects {
    group = "ch.trancee"
    version = rootProject.file("../VERSION").readText().trim()
}
