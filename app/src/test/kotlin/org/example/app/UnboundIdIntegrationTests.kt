package org.example.app

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.utility.DockerImageName
import java.time.Duration

/**
 * Integration tests for LDAP authentication using UnboundID (PingDirectory) Docker container.
 * This test class uses Testcontainers to start a PingDirectory Docker container and run tests against it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class UnboundIdIntegrationTests {

    companion object {
        /**
         * UnboundID (PingDirectory) Docker container configuration.
         * Using the PingDirectory image from Docker Hub.
         */
        @Container
        @JvmStatic
        val pingDirectoryContainer = GenericContainer(DockerImageName.parse("pingidentity/pingdirectory:latest"))
            .withExposedPorts(1389)
            .withEnv("PING_IDENTITY_ACCEPT_EULA", "YES")
            .withEnv("PING_IDENTITY_DEVOPS_USER", "user")
            .withEnv("PING_IDENTITY_DEVOPS_KEY", "key")
            .withEnv("PING_IDENTITY_PASSWORD", "admin_password")
            .withEnv("ROOT_USER_DN", "cn=administrator")
            .withEnv("ROOT_USER_PASSWORD", "admin_password")
            .withEnv("PING_IDENTITY_DEVOPS_REGISTRY", "docker.io/pingidentity")
            .withEnv("PING_IDENTITY_DEVOPS_TAG", "latest")
            .waitingFor(Wait.forLogMessage(".*PingDirectory has started.*", 1))
            .withStartupTimeout(Duration.ofSeconds(300))

        /**
         * Configure Spring Boot to use the UnboundID (PingDirectory) Docker container.
         */
        @JvmStatic
        @DynamicPropertySource
        fun configureProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.ldap.urls") { "ldap://${pingDirectoryContainer.host}:${pingDirectoryContainer.getMappedPort(1389)}" }
            registry.add("spring.ldap.base") { "dc=example,dc=org" }
            registry.add("spring.ldap.username") { "cn=administrator" }
            registry.add("spring.ldap.password") { "admin_password" }
            
            // Disable embedded LDAP server
            registry.add("spring.ldap.embedded.port") { "0" }
            
            // LDAP authentication
            registry.add("spring.security.ldap.base-dn") { "dc=example,dc=org" }
            registry.add("spring.security.ldap.user-search-base") { "ou=people" }
            registry.add("spring.security.ldap.user-search-filter") { "(uid={0})" }
            registry.add("spring.security.ldap.group-search-base") { "ou=groups" }
            registry.add("spring.security.ldap.group-search-filter") { "(member={0})" }
        }
    }

    @Autowired
    private lateinit var mockMvc: MockMvc

    /**
     * Test that the application context loads successfully with the UnboundID container.
     */
    @Test
    fun contextLoads() {
        // This test will fail if the application context cannot be loaded
    }

    /**
     * Test successful authentication with valid credentials.
     */
    @Test
    fun loginWithValidCredentialsSucceeds() {
        mockMvc.perform(
            formLogin("/login")
                .user("user1")
                .password("password1")
        )
            .andExpect(authenticated())
            .andExpect(redirectedUrl("/success"))
    }

    /**
     * Test failed authentication with invalid password.
     */
    @Test
    fun loginWithInvalidPasswordFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("user1")
                .password("wrongpassword")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
    }

    /**
     * Test failed authentication with non-existent user.
     */
    @Test
    fun loginWithNonExistentUserFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("nonexistentuser")
                .password("password")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
    }

    /**
     * Test authentication with admin credentials.
     */
    @Test
    fun loginWithAdminCredentialsSucceeds() {
        mockMvc.perform(
            formLogin("/login")
                .user("admin")
                .password("admin_password")
        )
            .andExpect(authenticated())
            .andExpect(redirectedUrl("/success"))
    }

    /**
     * Test authentication with locked user account.
     * UnboundID supports account locking through the ds-pwp-account-disabled attribute.
     */
    @Test
    fun loginWithLockedAccountFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("locked")
                .password("password")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
    }

    /**
     * Test authentication with expired password.
     * UnboundID supports password expiration through the ds-pwp-password-expiration-time attribute.
     */
    @Test
    fun loginWithExpiredPasswordFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("expired")
                .password("password")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
    }

    /**
     * Test authentication with special characters in credentials.
     */
    @Test
    fun loginWithSpecialCharactersInCredentials() {
        mockMvc.perform(
            formLogin("/login")
                .user("user.special")
                .password("p@ssw0rd!#$%")
        )
            .andExpect(authenticated())
            .andExpect(redirectedUrl("/success"))
    }

    /**
     * Test authentication with long credentials.
     */
    @Test
    fun loginWithLongCredentials() {
        mockMvc.perform(
            formLogin("/login")
                .user("user.long")
                .password("a".repeat(100))
        )
            .andExpect(authenticated())
            .andExpect(redirectedUrl("/success"))
    }

    /**
     * Test authentication with SQL injection attempt.
     */
    @Test
    fun loginWithSqlInjectionAttempt() {
        mockMvc.perform(
            formLogin("/login")
                .user("user' OR '1'='1")
                .password("password' OR '1'='1")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
    }

    /**
     * Test authentication with empty credentials.
     */
    @Test
    fun loginWithEmptyCredentialsFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("")
                .password("")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
    }

    /**
     * Test that protected resources require authentication.
     */
    @Test
    fun protectedResourceRequiresAuthentication() {
        mockMvc.perform(get("/success"))
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrlPattern("**/login"))
    }
}