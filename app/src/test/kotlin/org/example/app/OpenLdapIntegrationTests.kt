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
 * Integration tests for LDAP authentication using OpenLDAP Docker container.
 * This test class uses Testcontainers to start an OpenLDAP Docker container and run tests against it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class OpenLdapIntegrationTests {

    companion object {
        /**
         * OpenLDAP Docker container configuration.
         * Using the official OpenLDAP image from Docker Hub.
         */
        @Container
        @JvmStatic
        val openLdapContainer = GenericContainer(DockerImageName.parse("osixia/openldap:1.5.0"))
            .withExposedPorts(389)
            .withEnv("LDAP_ORGANISATION", "Example Inc.")
            .withEnv("LDAP_DOMAIN", "example.org")
            .withEnv("LDAP_ADMIN_PASSWORD", "admin")
            .withEnv("LDAP_CONFIG_PASSWORD", "config")
            .withCopyFileToContainer(
                MountableFile.forClasspathResource("ldap-test-data.ldif"),
                "/container/service/slapd/assets/config/bootstrap/ldif/custom/users.ldif"
            )
            .waitingFor(Wait.forLogMessage(".*slapd starting.*", 1))
            .withStartupTimeout(Duration.ofSeconds(60))

        /**
         * Configure Spring Boot to use the OpenLDAP Docker container.
         */
        @JvmStatic
        @DynamicPropertySource
        fun configureProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.ldap.urls") { "ldap://${openLdapContainer.host}:${openLdapContainer.getMappedPort(389)}" }
            registry.add("spring.ldap.base") { "dc=example,dc=org" }
            registry.add("spring.ldap.username") { "cn=admin,dc=example,dc=org" }
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
     * Test that the application context loads successfully with the OpenLDAP container.
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
     * Note: This test assumes the LDAP server has a user with a locked account.
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
     * Note: This test assumes the LDAP server has a user with an expired password.
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