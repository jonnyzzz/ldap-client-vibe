package org.example.app

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*

/**
 * Integration tests for LDAP authentication using Spring Boot's embedded LDAP server.
 * These tests use the same approach as LdapLoginApplicationTests but with additional test cases.
 */
@SpringBootTest
@AutoConfigureMockMvc
class UnboundIdLdapIntegrationTests {

    @Autowired
    private lateinit var mockMvc: MockMvc

    /**
     * Test that the application context loads successfully.
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
    }

    /**
     * Test authentication with special characters in credentials.
     */
    @Test
    fun loginWithSpecialCharactersInCredentialsFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("user1<script>alert('xss')</script>")
                .password("password1' OR '1'='1")
        )
            .andExpect(unauthenticated())
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

    /**
     * Test authentication with long username and password.
     */
    @Test
    fun loginWithLongCredentialsFails() {
        val longString = "a".repeat(1000)
        mockMvc.perform(
            formLogin("/login")
                .user(longString)
                .password(longString)
        )
            .andExpect(unauthenticated())
    }

    /**
     * Test authentication with SQL injection attempt in credentials.
     */
    @Test
    fun loginWithSqlInjectionAttemptFails() {
        mockMvc.perform(
            formLogin("/login")
                .user("user1'; DROP TABLE users; --")
                .password("password1' OR '1'='1")
        )
            .andExpect(unauthenticated())
    }
}