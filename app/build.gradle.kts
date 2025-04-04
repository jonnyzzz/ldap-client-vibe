plugins {
    // Apply the shared build logic from a convention plugin.
    // The shared code is located in `buildSrc/src/main/kotlin/kotlin-jvm.gradle.kts`.
    id("buildsrc.convention.kotlin-jvm")

    // Apply the Application plugin to add support for building an executable JVM application.
    application

    // Apply the Spring Boot plugin
    id("org.springframework.boot") version "3.2.3"
    id("io.spring.dependency-management") version "1.1.4"
}

dependencies {
    // Project "app" depends on project "utils". (Project paths are separated with ":", so ":utils" refers to the top-level "utils" project.)
    implementation(project(":utils"))

    // Spring Boot dependencies
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-thymeleaf")
    implementation("org.thymeleaf.extras:thymeleaf-extras-springsecurity6")

    // LDAP dependencies
    implementation("org.springframework.boot:spring-boot-starter-data-ldap")
    implementation("org.springframework.security:spring-security-ldap")
    implementation("com.unboundid:unboundid-ldapsdk")

    // Add Kotlin test dependency
    testImplementation(kotlin("test"))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")

    // Testcontainers dependencies
    testImplementation("org.testcontainers:testcontainers:1.19.3")
    testImplementation("org.testcontainers:junit-jupiter:1.19.3")

    // Selenium dependencies for UI testing
    testImplementation("org.seleniumhq.selenium:selenium-java:4.15.0")
    testImplementation("org.seleniumhq.selenium:selenium-chrome-driver:4.15.0")
    testImplementation("io.github.bonigarcia:webdrivermanager:5.6.2")

    // BrowserMob Proxy for network traffic interception
    testImplementation("net.lightbody.bmp:browsermob-core:2.1.5")
}

application {
    // Define the Fully Qualified Name for the application main class
    // (Note that Kotlin compiles `App.kt` to a class with FQN `com.example.app.AppKt`.)
    mainClass = "org.example.app.AppKt"
}
