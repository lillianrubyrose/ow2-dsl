plugins {
    kotlin("jvm") version "2.0.0"
    `java-library`
    `maven-publish`
}

group = "pm.lily"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    api("org.ow2.asm:asm:9.7")
    api("org.ow2.asm:asm-tree:9.7")
    api("org.ow2.asm:asm-commons:9.7")
    testImplementation(kotlin("test"))
}

publishing {
    publications {
        create<MavenPublication>("ow2-dsl") {
            from(components["java"])
        }
    }
}

tasks.test {
    useJUnitPlatform()
}
