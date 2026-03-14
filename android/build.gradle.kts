plugins {
    kotlin("jvm") version "2.3.0"
    id("com.vanniktech.maven.publish") version "0.30.0" apply false
}

allprojects {
    group = "ch.trancee"
    version = rootProject.file("../VERSION").readText().trim()
}
