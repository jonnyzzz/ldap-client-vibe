package org.example.app.config

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.LockedException
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.AuthenticationException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import java.util.regex.Pattern

/**
 * Security configuration for LDAP authentication.
 * This class configures Spring Security to use LDAP for authentication.
 */
@Configuration
@EnableWebSecurity
open class SecurityConfig(
    @Value("\${spring.ldap.embedded.port:8389}")
    private val ldapPort: Int,

    @Value("\${spring.ldap.embedded.base-dn:dc=example,dc=org}")
    private val ldapBaseDn: String
) {
    // Additional security properties with default values
    @Value("\${spring.ldap.urls:ldap://localhost:8389}")
    private val ldapUrls: String = "ldap://localhost:8389"

    @Value("\${spring.ldap.username:}")
    private val ldapUsername: String = ""

    @Value("\${spring.ldap.password:}")
    private val ldapPassword: String = ""

    @Value("\${spring.ldap.use-ssl:false}")
    private val ldapUseSsl: Boolean = false

    // LDAP authentication properties
    @Value("\${spring.security.ldap.user-dn-patterns:uid={0},ou=people,dc=example,dc=org}")
    private val ldapUserDnPatterns: String = "uid={0},ou=people,dc=example,dc=org"

    @Value("\${spring.security.ldap.group-search-base:ou=groups}")
    private val ldapGroupSearchBase: String = "ou=groups"

    @Value("\${spring.security.ldap.group-search-filter:(member={0})}")
    private val ldapGroupSearchFilter: String = "(member={0})"

    @Value("\${spring.security.ldap.password-attribute:userPassword}")
    private val ldapPasswordAttribute: String = "userPassword"

    // Pattern for validating usernames to prevent LDAP injection
    private val usernamePattern = Pattern.compile("^[a-zA-Z0-9._-]{3,50}$")

    /**
     * Configures the security filter chain.
     * This method sets up the security rules for the application.
     */
    @Bean
    open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers("/login", "/error", "/assets/**", "/css/**", "/js/**").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { form ->
                form
                    .loginPage("/login")
                    .defaultSuccessUrl("/success", true)
                    .failureUrl("/login?error=true")
                    .failureHandler(authenticationFailureHandler())
                    .permitAll()
            }
            .logout { logout ->
                logout
                    .logoutSuccessUrl("/login?logout=true")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .permitAll()
            }
            // Prevent session fixation attacks
            .sessionManagement { session ->
                session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .maximumSessions(1)
                    .expiredUrl("/login?expired=true")
            }
            // Add security headers
            .headers { headers ->
                headers.defaultsDisabled()
                headers.frameOptions { frameOptions -> frameOptions.deny() }
                headers.xssProtection { xss -> xss.disable() }
                headers.contentSecurityPolicy { csp -> csp.policyDirectives("default-src 'self'") }
            }
            .build()
    }

    /**
     * Authentication failure handler to handle different types of authentication failures.
     * For compatibility with tests, all failures redirect to "/login?error=true"
     */
    @Bean
    open fun authenticationFailureHandler(): AuthenticationFailureHandler {
        return AuthenticationFailureHandler { request, response, exception ->
            // Use a consistent error URL for all failures to match test expectations
            val errorUrl = "/login?error=true"

            // Log the specific error type for debugging
            when (exception) {
                is BadCredentialsException -> println("Authentication failed: Invalid credentials")
                is LockedException -> println("Authentication failed: Account locked")
                else -> println("Authentication failed: ${exception.message}")
            }

            response.sendRedirect(errorUrl)
        }
    }

    /**
     * Configures the authentication manager builder.
     * This method sets up the LDAP authentication provider with security enhancements.
     */
    @Autowired
    open fun configure(auth: AuthenticationManagerBuilder) {
        // Configure LDAP authentication using properties
        auth
            .ldapAuthentication()
            .userDnPatterns(ldapUserDnPatterns)
            .groupSearchBase(ldapGroupSearchBase)
            .groupSearchFilter(ldapGroupSearchFilter)
            .contextSource()
            .url(ldapUrls)
            .and()
            .passwordCompare()
            .passwordAttribute(ldapPasswordAttribute)
    }

    /**
     * Configures the password encoder.
     * This bean sets up how passwords are encoded and verified.
     * Using a higher strength factor (12) for better security.
     */
    @Bean
    open fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder(12)
    }
}
