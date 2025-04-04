# LDAP Authentication Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [LDAP Configuration](#ldap-configuration)
   - [Basic Configuration](#basic-configuration)
   - [Embedded LDAP Server](#embedded-ldap-server)
   - [External LDAP Server](#external-ldap-server)
3. [LDAP Directory Structure](#ldap-directory-structure)
   - [Users and Groups](#users-and-groups)
   - [LDIF Format](#ldif-format)
4. [Authentication Flow](#authentication-flow)
   - [How Authentication Works](#how-authentication-works)
   - [Password Comparison vs. Binding](#password-comparison-vs-binding)
5. [Security Configuration](#security-configuration)
   - [Spring Security Integration](#spring-security-integration)
   - [Authorization Rules](#authorization-rules)
6. [Edge Cases and Troubleshooting](#edge-cases-and-troubleshooting)
   - [Common Issues](#common-issues)
   - [Security Considerations](#security-considerations)
   - [Error Handling](#error-handling)
7. [Best Practices](#best-practices)
   - [Configuration](#configuration-best-practices)
   - [Security](#security-best-practices)
   - [Testing](#testing-best-practices)

## Introduction

This application uses Lightweight Directory Access Protocol (LDAP) for authentication. LDAP is a standard protocol for accessing and maintaining distributed directory information services over an IP network. In this application, LDAP is used to authenticate users and determine their roles/permissions.

The implementation uses Spring Security's LDAP authentication support, which provides a robust and secure way to integrate LDAP authentication into a Spring Boot application.

## LDAP Configuration

### Basic Configuration

The LDAP configuration is defined in the `application.properties` file. Here are the key configuration properties:

```properties
# LDAP configuration
spring.ldap.urls=ldap://localhost:8389
spring.ldap.base=dc=example,dc=org
spring.ldap.username=uid=admin,dc=example,dc=org
spring.ldap.password=admin

# LDAP authentication
spring.security.ldap.base-dn=dc=example,dc=org
spring.security.ldap.user-search-base=ou=people
spring.security.ldap.user-search-filter=(uid={0})
spring.security.ldap.group-search-base=ou=groups
spring.security.ldap.group-search-filter=(uniqueMember={0})
```

These properties define:
- The LDAP server URL
- The base DN (Distinguished Name) for the LDAP directory
- The admin credentials for accessing the LDAP server
- The search base and filter for finding users
- The search base and filter for finding groups

### Embedded LDAP Server

For development and testing, the application uses Spring Boot's embedded LDAP server. This is configured with the following properties:

```properties
# Embedded LDAP server configuration
spring.ldap.embedded.port=8389
spring.ldap.embedded.ldif=classpath:ldap-data.ldif
spring.ldap.embedded.base-dn=dc=example,dc=org
spring.ldap.embedded.credential.username=uid=admin
spring.ldap.embedded.credential.password=admin
```

The embedded LDAP server:
- Runs on port 8389
- Uses the LDIF file at `classpath:ldap-data.ldif` to populate the directory
- Has a base DN of `dc=example,dc=org`
- Uses admin credentials with username `uid=admin` and password `admin`

### External LDAP Server

To use an external LDAP server instead of the embedded one, you need to:

1. Remove or comment out the embedded LDAP configuration
2. Update the LDAP URL to point to your external LDAP server
3. Update the base DN and credentials as needed

Example configuration for an external LDAP server:

```properties
# External LDAP server configuration
spring.ldap.urls=ldap://ldap.example.org:389
spring.ldap.base=dc=example,dc=org
spring.ldap.username=cn=admin,dc=example,dc=org
spring.ldap.password=your-admin-password

# LDAP authentication
spring.security.ldap.base-dn=dc=example,dc=org
spring.security.ldap.user-search-base=ou=people
spring.security.ldap.user-search-filter=(uid={0})
spring.security.ldap.group-search-base=ou=groups
spring.security.ldap.group-search-filter=(uniqueMember={0})
```

## LDAP Directory Structure

### Users and Groups

The LDAP directory is structured with organizational units (OUs) for people and groups:

- `ou=people,dc=example,dc=org`: Contains user entries
- `ou=groups,dc=example,dc=org`: Contains group entries

Users are defined with the following attributes:
- `uid`: User ID (used for authentication)
- `cn`: Common Name
- `sn`: Surname
- `userPassword`: Password

Groups are defined with the following attributes:
- `cn`: Common Name (group name)
- `uniqueMember`: DNs of users who are members of the group

### LDIF Format

The LDAP directory is defined in LDIF (LDAP Data Interchange Format) in the `ldap-data.ldif` file. Here's an example of the LDIF format:

```ldif
# Base organization
dn: dc=example,dc=org
objectClass: top
objectClass: domain
dc: example

# Organizational units
dn: ou=people,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: groups

# Users
dn: uid=user1,ou=people,dc=example,dc=org
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: User One
sn: One
uid: user1
userPassword: password1

# Groups
dn: cn=users,ou=groups,dc=example,dc=org
objectClass: top
objectClass: groupOfUniqueNames
cn: users
uniqueMember: uid=user1,ou=people,dc=example,dc=org
```

## Authentication Flow

### How Authentication Works

When a user attempts to log in, the following process occurs:

1. The user submits their username and password to the `/login` endpoint
2. Spring Security's LDAP authentication provider processes the login request
3. The provider searches for the user in the LDAP directory using the configured user search base and filter
4. If the user is found, the provider verifies the password
5. If authentication is successful, the user is redirected to the success page
6. If authentication fails, the user is redirected to the login page with an error message

### Password Comparison vs. Binding

The application uses the password comparison method for authentication, as configured in `SecurityConfig.kt`:

```kotlin
auth
    .ldapAuthentication()
    .userSearchBase("ou=people")
    .userSearchFilter("(uid={0})")
    .groupSearchBase("ou=groups")
    .groupSearchFilter("(uniqueMember={0})")
    .contextSource()
    .url("ldap://localhost:$ldapPort/$ldapBaseDn")
    .and()
    .passwordCompare()
    .passwordAttribute("userPassword")
```

With password comparison:
- The application retrieves the user's password from LDAP
- The application compares the provided password with the stored password
- No direct binding to LDAP with the user's credentials is performed

An alternative approach is binding authentication, where the application attempts to bind to LDAP with the user's credentials. To use binding authentication, you would remove the `.passwordCompare()` section from the configuration.

## Security Configuration

### Spring Security Integration

LDAP authentication is integrated with Spring Security in the `SecurityConfig` class. The key components are:

1. Security Filter Chain: Configures URL access rules, login/logout behavior, and session management
2. Authentication Manager: Configures the LDAP authentication provider
3. Password Encoder: Configures how passwords are encoded and verified

```kotlin
@Configuration
@EnableWebSecurity
open class SecurityConfig(
    @Value("\${spring.ldap.embedded.port:8389}")
    private val ldapPort: Int,

    @Value("\${spring.ldap.embedded.base-dn:dc=example,dc=org}")
    private val ldapBaseDn: String
) {
    @Bean
    open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .authorizeHttpRequests { authorize ->
                authorize
                    .requestMatchers("/login", "/error").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { form ->
                form
                    .loginPage("/login")
                    .defaultSuccessUrl("/success", true)
                    .failureUrl("/login?error=true")
                    .permitAll()
            }
            .logout { logout ->
                logout
                    .logoutSuccessUrl("/login?logout=true")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .permitAll()
            }
            .build()
    }

    @Autowired
    open fun configure(auth: AuthenticationManagerBuilder) {
        auth
            .ldapAuthentication()
            .userSearchBase("ou=people")
            .userSearchFilter("(uid={0})")
            .groupSearchBase("ou=groups")
            .groupSearchFilter("(uniqueMember={0})")
            .contextSource()
            .url("ldap://localhost:$ldapPort/$ldapBaseDn")
            .and()
            .passwordCompare()
            .passwordAttribute("userPassword")
    }

    @Bean
    open fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }
}
```

### Authorization Rules

The application uses a simple authorization model:
- Public access to `/login` and `/error` endpoints
- All other endpoints require authentication

For more complex authorization rules, you could:
1. Use the `.hasRole()` or `.hasAuthority()` methods to restrict access based on roles/authorities
2. Implement method-level security with `@PreAuthorize` annotations
3. Use expression-based access control for more complex rules

Example of role-based authorization:

```kotlin
http.authorizeHttpRequests { authorize ->
    authorize
        .requestMatchers("/login", "/error").permitAll()
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated()
}
```

## Edge Cases and Troubleshooting

### Common Issues

1. **Connection Issues**
   - **Symptom**: Unable to connect to LDAP server
   - **Solution**: Verify LDAP URL, port, and network connectivity

2. **Authentication Failures**
   - **Symptom**: Valid users unable to authenticate
   - **Solution**: Check user search base, user search filter, and password comparison configuration

3. **Authorization Issues**
   - **Symptom**: Users can authenticate but not access certain resources
   - **Solution**: Check group search base, group search filter, and authorization rules

4. **LDAP Schema Mismatch**
   - **Symptom**: User attributes not found or incorrect
   - **Solution**: Ensure LDAP schema matches the expected attributes in the application

### Security Considerations

1. **Password Security**
   - Store passwords securely in LDAP (hashed, not plaintext)
   - Use TLS/SSL for LDAP connections (ldaps://)
   - Consider implementing password policies (complexity, expiration)

2. **Input Validation**
   - Validate usernames and passwords to prevent injection attacks
   - Handle special characters properly

3. **Account Lockout**
   - Implement account lockout policies for failed login attempts
   - Consider using a real LDAP server with account lockout support

4. **Session Security**
   - Implement proper session management (timeout, invalidation)
   - Use secure cookies

### Error Handling

The application handles various error cases:

1. **Invalid Credentials**
   - Redirects to `/login?error=true`
   - Displays "Invalid username or password" message

2. **Non-existent Users**
   - Handled the same as invalid credentials
   - Does not reveal whether the username exists

3. **Special Characters in Credentials**
   - Properly escapes special characters to prevent injection attacks

4. **Long Credentials**
   - Handles excessively long usernames and passwords gracefully

5. **LDAP Server Issues**
   - Gracefully handles LDAP server unavailability
   - Provides appropriate error messages

## Best Practices

### Configuration Best Practices

1. **Externalize Configuration**
   - Store LDAP configuration in environment variables or a secure configuration service
   - Don't hardcode credentials in the application code

2. **Use Connection Pooling**
   - Enable LDAP connection pooling for better performance
   - Configure appropriate pool size based on expected load

3. **Implement Failover**
   - Configure multiple LDAP servers for high availability
   - Implement retry logic for transient LDAP errors

4. **Use TLS/SSL**
   - Always use secure LDAP connections (ldaps://) in production
   - Validate server certificates

### Security Best Practices

1. **Principle of Least Privilege**
   - Use a service account with minimal permissions for LDAP access
   - Don't use the LDAP admin account for regular operations

2. **Secure Password Handling**
   - Use password comparison instead of binding when possible
   - Implement proper password hashing

3. **Audit Logging**
   - Log authentication attempts (success and failure)
   - Monitor for suspicious activity

4. **Regular Security Reviews**
   - Regularly review LDAP configuration and access controls
   - Keep LDAP server software updated

### Testing Best Practices

1. **Use Embedded LDAP for Testing**
   - Use Spring Boot's embedded LDAP server for unit and integration tests
   - Define test-specific LDIF files

2. **Test Edge Cases**
   - Test authentication with invalid credentials
   - Test with special characters in usernames and passwords
   - Test with long inputs
   - Test with SQL injection and XSS attempts

3. **Performance Testing**
   - Test LDAP authentication under load
   - Verify connection pooling works as expected

4. **Integration Testing**
   - Test with a real LDAP server in a staging environment
   - Verify all authentication and authorization flows
