import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.allopen.gradle.*
import org.jetbrains.kotlin.gradle.tasks.*
import kotlinx.benchmark.gradle.*

version = "0.11.2-SNAPSHOT"

group = "com.ironcorelabs"

plugins {
    // Apply the org.jetbrains.kotlin.jvm Plugin to add support for Kotlin.
    kotlin("jvm") version "1.9.23"
    id("org.jetbrains.dokka") version "1.9.20"

    // Apply the java-library plugin for API and implementation separation.
    `java-library`

    `maven-publish`
    signing
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0-rc-1"
    id("com.dorongold.task-tree") version "2.1.1"

    // benchmark deps
    java
    id("org.jetbrains.kotlinx.benchmark") version "0.4.10"
    kotlin("plugin.allopen") version "1.9.23"
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions { jvmTarget = "17" }
}

tasks.register<Jar>("dokkaJavadocJar") {
    dependsOn(tasks.dokkaJavadoc)
    from(tasks.dokkaJavadoc.flatMap { it.outputDirectory })
    archiveClassifier.set("javadoc")
}

val benchmarks = "benchmarks"
sourceSets {
    create(benchmarks)
}

sourceSets.all {
    java.setSrcDirs(listOf("$name/src"))

    resources.setSrcDirs(listOf("$name/../src/main/resources"))
}

val benchmarksImplementation by configurations

dependencies {
    // Use the Kotlin JUnit 5 integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    // Use the JUnit 5 integration.
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.9.1")
    implementation("net.java.dev.jna:jna:5.14.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
    implementation("org.jetbrains.kotlin:kotlin-scripting-jvm")
    benchmarksImplementation("org.jetbrains.kotlinx:kotlinx-benchmark-runtime:0.4.9")
    benchmarksImplementation(sourceSets.main.get().output + sourceSets.main.get().runtimeClasspath)
}

java {
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

nexusPublishing { repositories { sonatype() } }

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            groupId = "com.ironcorelabs"
            artifactId = "ironcore-alloy"
            pom {
                name.set("IronCore Labs Alloy SDK")
                description.set("IronCore Alloy bindings for Kotlin.")
                url.set("https://ironcorelabs.com")
                licenses {
                    license {
                        name.set("GNU Affero General Public License v3 or later (AGPLv3+)")
                        url.set("https://www.gnu.org/licenses/agpl-3.0.en.html#license-text")
                    }
                }
                developers {
                    developer {
                        id.set("IronCore Labs")
                        name.set("IronCore Labs")
                        email.set("code@ironcorelabs.com")
                    }
                }
                scm {
                    connection.set("scm:git@github.com:IronCoreLabs/ironcore-alloy.git")
                    url.set("https://github.com/IronCoreLabs")
                }
            }
            artifact(tasks["dokkaJavadocJar"])
        }
    }
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

tasks.named<Test>("test") {
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()
    testLogging {
        exceptionFormat = TestExceptionFormat.FULL
        events = mutableSetOf(TestLogEvent.FAILED, TestLogEvent.PASSED, TestLogEvent.SKIPPED)
        showStandardStreams = true
    }
}

signing {
    useGpgCmd()
    sign(publishing.publications["mavenJava"])
}

configure<AllOpenExtension> { annotation("org.openjdk.jmh.annotations.State") }

benchmark {
    targets {
        register(benchmarks) {
            this as JvmBenchmarkTarget
            jmhVersion = "1.37"
        }
    }
}
