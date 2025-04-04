package org.example.app

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledOnOs
import org.junit.jupiter.api.condition.OS
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
 * Integration tests for LDAP authentication using Active Directory Docker container.
 * This test class uses Testcontainers to start an Active Directory Docker container and run tests against it.
 * 
 * NOTE: These tests require Windows containers, which are only supported on Windows hosts.
 * The tests are automatically skipped on non-Windows platforms.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@EnabledOnOs(OS.WINDOWS)  // Only run on Windows, as Active Directory containers require Windows
class ActiveDirectoryIntegrationTests {

    companion object {
        /**
         * Active Directory Docker container configuration.
         * Using the Windows Server Core with IIS image from Microsoft.
         */
        @Container
        @JvmStatic
        val activeDirectoryContainer = GenericContainer(DockerImageName.parse("mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019"))
            .withExposedPorts(389)
            .withEnv("DOMAIN_NAME", "example.org")
            .withEnv("ADMIN_PASSWORD", "admin_password")
            .waitingFor(Wait.forLogMessage(".*Active Directory Domain Services is ready.*", 1))
            .withStartupTimeout(Duration.ofSeconds(600))  // AD can take a long time to start

        /**
         * Configure Spring Boot to use the Active Directory Docker container.
         */
        @JvmStatic
        @DynamicPropertySource
        fun configureProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.ldap.urls") { "ldap://${activeDirectoryContainer.host}:${activeDirectoryContainer.getMappedPort(389)}" }
            registry.add("spring.ldap.base") { "dc=example,dc=org" }
            registry.add("spring.ldap.username") { "cn=Administrator,cn=Users,dc=example,dc=org" }
            registry.add("spring.ldap.password") { "admin_password" }
            
            // Disable embedded LDAP server
            registry.add("spring.ldap.embedded.port") { "0" }
            
            // LDAP authentication
            registry.add("spring.security.ldap.base-dn") { "dc=example,dc=org" }
            registry.add("spring.security.ldap.user-search-base") { "cn=Users" }
            registry.add("spring.security.ldap.user-search-filter") { "(sAMAccountName={0})" }  // AD uses sAMAccountName
            registry.add("spring.security.ldap.group-search-base") { "cn=Groups" }
            registry.add("spring.security.ldap.group-search-filter") { "(member={0})" }
        }
    }

    @Autowired
    private lateinit var mockMvc: MockMvc

    /**
     * Test that the application context loads successfully with the Active Directory container.
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
                .user("Administrator")
                .password("admin_password")
        )
            .andExpect(authenticated())
            .andExpect(redirectedUrl("/success"))
    }

    /**
     * Test authentication with locked user account.
     * Active Directory supports account locking through the userAccountControl attribute.
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
     * Active Directory supports password expiration through the pwdLastSet attribute.
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