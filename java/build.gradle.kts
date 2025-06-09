import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent

version = "0.12.2-SNAPSHOT"

group = "com.ironcorelabs"

plugins {
    // Apply the java-library plugin for API and implementation separation.
    `java-library`
    `maven-publish`
    signing
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0-rc-1"
    id("com.dorongold.task-tree") version "2.1.1"

    // benchmark deps
    id("me.champeau.jmh") version "0.7.2"
}

dependencies {
    // Use the JUnit 5 integration.
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.1")
    testImplementation("com.squareup.okhttp3:okhttp:4.12.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    implementation("net.java.dev.jna:jna:5.14.0")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withSourcesJar()
    withJavadocJar()
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

nexusPublishing { repositories { sonatype() } }

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            groupId = "com.ironcorelabs"
            artifactId = "ironcore-alloy-java"
            pom {
                name.set("IronCore Labs Alloy SDK")
                description.set("IronCore Alloy bindings for Java.")
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
        }
    }
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

tasks.test {
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
   
