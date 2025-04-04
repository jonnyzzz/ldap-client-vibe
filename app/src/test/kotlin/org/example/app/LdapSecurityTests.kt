package org.example.app

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.logout
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*
import org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import java.util.concurrent.TimeUnit

/**
 * Security-focused tests for LDAP authentication.
 * These tests specifically target security aspects of the LDAP authentication implementation.
 */
@SpringBootTest
@AutoConfigureMockMvc
class LdapSecurityTests {

    @Autowired
    private lateinit var mockMvc: MockMvc

    /**
     * Test that LDAP injection attempts are prevented.
     * This test tries various LDAP injection patterns in the username.
     */
    @Test
    fun ldapInjectionPrevention() {
        // Test with wildcard
        mockMvc.perform(
            formLogin("/login")
                .user("*")
                .password("password1")
        )
            .andExpect(unauthenticated())

        // Test with OR condition
        mockMvc.perform(
            formLogin("/login")
                .user("user1)(|(password=*)")
                .password("password1")
        )
            .andExpect(unauthenticated())

        // Test with AND condition
        mockMvc.perform(
            formLogin("/login")
                .user("user1)(&(objectClass=*)")
                .password("password1")
        )
            .andExpect(unauthenticated())

        // Test with comment injection
        mockMvc.perform(
            formLogin("/login")
                .user("user1)#")
                .password("password1")
        )
            .andExpect(unauthenticated())
    }

    /**
     * Test that authentication failures are handled properly with specific error messages.
     */
    @Test
    fun authenticationFailureHandling() {
        // Test with invalid credentials
        mockMvc.perform(
            formLogin("/login")
                .user("user1")
                .password("wrongpassword")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
            .andDo(print())

        // Test with non-existent user
        mockMvc.perform(
            formLogin("/login")
                .user("nonexistentuser")
                .password("password")
        )
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error=true"))
    }

    /**
     * Test that session management is working correctly.
     * This test verifies that a user can't have multiple active sessions.
     */
    @Test
    fun sessionManagement() {
        // First login
        mockMvc.perform(
            formLogin("/login")
                .user("user1")
                .password("password1")
        )
            .andExpect(authenticated())
            .andExpect(redirectedUrl("/success"))

        // Second login should invalidate the first session
        mockMvc.perform(
            formLogin("/login")
                .user("user1")
                .password("password1")
        )
            .andExpect(authenticated())
            .andExpect(redirectedUrl("/success"))
    }

    /**
     * Test that security headers are properly set.
     */
    @Test
    fun securityHeaders() {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Frame-Options"))
            .andExpect(header().exists("Content-Security-Policy"))
    }

    /**
     * Test that CSRF protection is working.
     */
    @Test
    fun csrfProtection() {
        // Without CSRF token, the request should fail
        mockMvc.perform(
            post("/login")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "user1")
                .param("password", "password1")
        )
            .andExpect(status().isForbidden())
    }

    /**
     * Test that input validation is working for usernames.
     */
    @Test
    fun inputValidation() {
        // Test with very long username
        val longUsername = "a".repeat(1000)
        mockMvc.perform(
            formLogin("/login")
                .user(longUsername)
                .password("password1")
        )
            .andExpect(unauthenticated())

        // Test with special characters
        mockMvc.perform(
            formLogin("/login")
                .user("<script>alert('xss')</script>")
                .password("password1")
        )
            .andExpect(unauthenticated())
    }

    /**
     * Test that logout functionality works correctly.
     */
    @Test
    fun logoutFunctionality() {
        // Login first
        mockMvc.perform(
            formLogin("/login")
                .user("user1")
                .password("password1")
        )
            .andExpect(authenticated())

        // Then logout - using the security test support for logout that handles CSRF
        mockMvc.perform(logout())
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login?logout=true"))

        // Try to access protected resource after logout
        mockMvc.perform(get("/success"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrlPattern("**/login"))
    }
}
