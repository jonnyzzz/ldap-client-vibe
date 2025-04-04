package org.example.app

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

// Application version
const val APP_VERSION = "1.0.0"

/**
 * Spring Boot Application main class.
 * This class serves as the entry point for the LDAP login server application.
 */
@SpringBootApplication
open class LdapLoginApplication

/**
 * Main function that starts the Spring Boot application.
 * Supports the following commands:
 * -version: Displays the application version
 * -help: Displays help information
 */
fun main(args: Array<String> = emptyArray()) {
    // Handle command-line arguments
    when {
        args.contains("-version") -> {
            println("Version: $APP_VERSION")
            return
        }
        args.contains("-help") -> {
            println("Usage: app [-version] [-help]")
            println("Options:")
            println("  -version    Displays the application version")
            println("  -help       Displays this help message")
            return
        }
    }

    // Start the Spring Boot application
    runApplication<LdapLoginApplication>(*args)
}
