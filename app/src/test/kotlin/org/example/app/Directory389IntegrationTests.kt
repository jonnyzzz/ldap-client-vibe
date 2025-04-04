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
import org.testcontainers.utility.MountableFile
import java.time.Duration

/**
 * Integration tests for LDAP authentication using 389 Directory Server Docker container.
 * This test class uses Testcontainers to start a 389 Directory Server Docker container and run tests against it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class Directory389IntegrationTests {

    companion object {
        /**
         * 389 Directory Server Docker container configuration.
         * Using the 389 Directory Server image from Docker Hub.
         */
        @Container
        @JvmStatic
        val directory389Container = GenericContainer(DockerImageName.parse("389ds/dirsrv:2.4"))
            .withExposedPorts(3389)
            .withEnv("DS_DM_PASSWORD", "admin")
            .withEnv("DS_SUFFIX_NAME", "example")
            .withEnv("DS_SUFFIX", "dc=example,dc=org")
            .waitingFor(Wait.forLogMessage(".*389-Directory/2.4.*", 1))
            .withStartupTimeout(Duration.ofSeconds(120))

        /**
         * Configure Spring Boot to use the 389 Directory Server Docker container.
         */
        @JvmStatic
        @DynamicPropertySource
        fun configureProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.ldap.urls") { "ldap://${directory389Container.host}:${directory389Container.getMappedPort(3389)}" }
            registry.add("spring.ldap.base") { "dc=example,dc=org" }
            registry.add("spring.ldap.username") { "cn=Directory Manager" }
            registry.add("spring.ldap.password") { "admin" }
            
            // Disable embedded LDAP server
            registry.add("spring.ldap.embedded.port") { "0" }
            
            // LDAP authentication
            registry.add("spring.security.ldap.base-dn") { "dc=example,dc=org" }
            registry.add("spring.security.ldap.user-search-base") { "ou=people" }
            registry.add("spring.security.ldap.user-search-filter") { "(uid={0})" }
            registry.add("spring.security.ldap.group-search-base") { "ou=groups" }
            registry.add("spring.security.ldap.group-search-filter") { "(uniqueMember={0})" }
        }
    }

    @Autowired
    private lateinit var mockMvc: MockMvc

    /**
     * Test that the application context loads successfully with the 389 Directory Server container.
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
                .password("admin")
        )
            .andExpect(authenticated())
            .andExpect(redirectedUrl("/success"))
    }

    /**
     * Test authentication with locked user account.
     * 389 Directory Server supports account locking through the nsAccountLock attribute.
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
     * 389 Directory Server supports password expiration through the passwordExpirationTime attribute.
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
     * Test that protected resources require authentication.
     */
    @Test
    fun protectedResourceRequiresAuthentication() {
        mockMvc.perform(get("/success"))
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrlPattern("**/login"))
    }
}