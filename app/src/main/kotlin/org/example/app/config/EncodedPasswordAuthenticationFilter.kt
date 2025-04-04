package org.example.app.config

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationServiceException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import java.util.Base64

/**
 * Custom authentication filter that handles encoded passwords.
 * This filter intercepts login requests, extracts the encoded password,
 * decodes it, and uses it for authentication.
 */
class EncodedPasswordAuthenticationFilter(
    authenticationManager: AuthenticationManager
) : UsernamePasswordAuthenticationFilter(authenticationManager) {

    init {
        // Set the request matcher to only process POST requests to /login
        setRequiresAuthenticationRequestMatcher(AntPathRequestMatcher("/login", "POST"))
    }

    /**
     * Attempt to authenticate the user with the provided credentials.
     * This method extracts the encoded password from the request, decodes it,
     * and uses it for authentication.
     */
    override fun attemptAuthentication(request: HttpServletRequest, response: HttpServletResponse): Authentication {
        if (request.method != "POST") {
            throw AuthenticationServiceException("Authentication method not supported: ${request.method}")
        }

        val username = obtainUsername(request) ?: ""
        val encodedPassword = request.getParameter("encodedPassword") ?: ""
        
        // If encodedPassword is provided, decode it and use it for authentication
        val password = if (encodedPassword.isNotEmpty()) {
            try {
                String(Base64.getDecoder().decode(encodedPassword))
            } catch (e: IllegalArgumentException) {
                // If decoding fails, log the error and use an empty password
                logger.warn("Failed to decode password: ${e.message}")
                ""
            }
        } else {
            // Fallback to the regular password field if encodedPassword is not provided
            obtainPassword(request) ?: ""
        }

        // Create the authentication token with the username and decoded password
        val authRequest = UsernamePasswordAuthenticationToken(username.trim(), password)
        
        // Allow subclasses to set the "details" property
        setDetails(request, authRequest)
        
        // Perform the authentication
        return authenticationManager.authenticate(authRequest)
    }
}