import org.gradle.api.tasks.JavaExec

plugins {
    id("org.jetbrains.kotlin.jvm")
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
    implementation(project(":noise-crypto"))
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("convertOfficialNoiseVectors") {
    group = "verification"
    description = "Convert directly translatable official Noise wiki vectors into shared v1 fixture JSON files."
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set("noise.protocol.testing.OfficialNoiseVectorConverterCliKt")

    val inputPath = providers.gradleProperty("officialNoiseInput")
    val outputDirectory = providers.gradleProperty("officialNoiseOutput")
    val schemaPath = providers.gradleProperty("officialNoiseSchema")
        .orElse("../../schema/noise-vector-v1.schema.json")

    doFirst {
        require(inputPath.isPresent) {
            "Provide -PofficialNoiseInput=/absolute/path/to/official-vectors.json"
        }
        require(outputDirectory.isPresent) {
            "Provide -PofficialNoiseOutput=/absolute/path/to/output-directory"
        }

        args(
            "--input", inputPath.get(),
            "--output-dir", outputDirectory.get(),
            "--schema-path", schemaPath.get()
        )
    }
}
