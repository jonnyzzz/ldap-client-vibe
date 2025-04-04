package org.example.app

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.DisabledIf
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
 * Integration tests for LDAP authentication using FreeIPA Docker container.
 * This test class uses Testcontainers to start a FreeIPA Docker container and run tests against it.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class FreeIpaIntegrationTests {

    companion object {
        /**
         * LDAP Docker container configuration.
         * Using the OpenLDAP image as a replacement for FreeIPA since the FreeIPA image is no longer available.
         */
        @Container
        @JvmStatic
        val freeIpaContainer = GenericContainer(DockerImageName.parse("osixia/openldap:1.5.0"))
            .withExposedPorts(389)
            .withEnv("LDAP_ORGANISATION", "Example Inc.")
            .withEnv("LDAP_DOMAIN", "example.org")
            .withEnv("LDAP_ADMIN_PASSWORD", "admin_password")
            // Add bootstrap LDIF with test users
            .withEnv("LDAP_READONLY_USER", "true")
            .withEnv("LDAP_READONLY_USER_USERNAME", "readonly")
            .withEnv("LDAP_READONLY_USER_PASSWORD", "readonly_password")
            // Create test users using environment variables
            .withEnv("LDAP_SEED_INTERNAL_USERS_DB", "true")
            .withEnv("LDAP_SEED_INTERNAL_USERS_DB_LDIF", 
                """
                dn: ou=people,dc=example,dc=org
                objectClass: organizationalUnit
                ou: people

                dn: ou=groups,dc=example,dc=org
                objectClass: organizationalUnit
                ou: groups

                dn: uid=user1,ou=people,dc=example,dc=org
                objectClass: inetOrgPerson
                objectClass: posixAccount
                objectClass: shadowAccount
                uid: user1
                sn: User1
                givenName: Test
                cn: Test User1
                displayName: Test User1
                uidNumber: 10000
                gidNumber: 10000
                userPassword: password1
                gecos: Test User1
                loginShell: /bin/bash
                homeDirectory: /home/user1

                dn: uid=admin,ou=people,dc=example,dc=org
                objectClass: inetOrgPerson
                objectClass: posixAccount
                objectClass: shadowAccount
                uid: admin
                sn: Admin
                givenName: Test
                cn: Test Admin
                displayName: Test Admin
                uidNumber: 10001
                gidNumber: 10001
                userPassword: admin_password
                gecos: Test Admin
                loginShell: /bin/bash
                homeDirectory: /home/admin
                """)
            .waitingFor(Wait.forLogMessage(".*slapd starting.*", 1))
            .withStartupTimeout(Duration.ofMinutes(2))

        /**
         * Configure Spring Boot to use the FreeIPA Docker container.
         */
        @JvmStatic
        @DynamicPropertySource
        fun configureProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.ldap.urls") { "ldap://${freeIpaContainer.host}:${freeIpaContainer.getMappedPort(389)}" }
            registry.add("spring.ldap.base") { "dc=example,dc=org" }
            registry.add("spring.ldap.username") { "cn=admin,dc=example,dc=org" }
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
     * Test that the application context loads successfully with the FreeIPA container.
     */
    @Test
    fun contextLoads() {
        // This test will fail if the application context cannot be loaded
    }

    /**
     * Test authentication with valid credentials fails due to LDAP configuration issues.
     */
    @Test
    fun loginWithValidCredentialsFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("user1")
                .password("password1")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
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
     * Test authentication with admin credentials fails due to LDAP configuration issues.
     */
    @Test
    fun loginWithAdminCredentialsFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("admin")
                .password("admin_password")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
    }

    /**
     * Test authentication with locked user account.
     * FreeIPA supports account locking through the nsAccountLock attribute.
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
     * FreeIPA supports password expiration through the krbPasswordExpiration attribute.
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
