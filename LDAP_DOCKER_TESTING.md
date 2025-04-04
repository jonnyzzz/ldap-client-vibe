# LDAP Docker Testing Documentation

## Overview

This document provides information about the Docker-based LDAP testing infrastructure implemented in this project. The infrastructure allows testing the application's LDAP authentication functionality against various LDAP server implementations.

## LDAP Servers

The following LDAP servers are available as Docker containers and have been integrated with the testing infrastructure:

1. **OpenLDAP**
   - Docker Image: `osixia/openldap:1.5.0`
   - Port: 389
   - Admin DN: `cn=admin,dc=example,dc=org`
   - Account Locking: Via `pwdLockout` attribute
   - Password Expiration: Via `pwdMaxAge` attribute

2. **ApacheDS**
   - Docker Image: `apache/directory-server:2.0.0-M24`
   - Port: 10389
   - Admin DN: `uid=admin,ou=system`
   - Account Locking: Via `pwdLockout` attribute
   - Password Expiration: Via `pwdMaxAge` attribute

3. **389 Directory Server**
   - Docker Image: `389ds/dirsrv:2.4`
   - Port: 3389
   - Admin DN: `cn=Directory Manager`
   - Account Locking: Via `nsAccountLock` attribute
   - Password Expiration: Via `passwordExpirationTime` attribute

4. **OpenDJ**
   - Docker Image: `openidentityplatform/opendj:4.5.0`
   - Port: 1389
   - Admin DN: `cn=Directory Manager`
   - Account Locking: Via `ds-pwp-account-disabled` attribute
   - Password Expiration: Via `pwdEndTime` attribute

5. **UnboundID (PingDirectory)**
   - Docker Image: `pingidentity/pingdirectory:latest`
   - Port: 1389
   - Admin DN: `cn=administrator`
   - Account Locking: Via `ds-pwp-account-disabled` attribute
   - Password Expiration: Via `ds-pwp-password-expiration-time` attribute

6. **Active Directory**
   - Docker Image: `mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019`
   - Port: 389
   - Admin DN: `cn=Administrator,cn=Users,dc=example,dc=org`
   - Account Locking: Via `userAccountControl` attribute
   - Password Expiration: Via `pwdLastSet` attribute

7. **FreeIPA**
   - Docker Image: `freeipa/freeipa-server:centos-8`
   - Port: 389
   - Admin DN: `uid=admin,cn=users,cn=accounts,dc=example,dc=org`
   - Account Locking: Via `nsAccountLock` attribute
   - Password Expiration: Via `krbPasswordExpiration` attribute

## Test Cases

The following test cases are implemented for each LDAP server:

1. **Basic Authentication Tests**
   - Successful login with valid credentials
   - Failed login with invalid password
   - Failed login with non-existent user
   - Successful login with admin credentials
   - Failed login with empty credentials

2. **Security Tests**
   - Login with special characters in credentials
   - Login with long credentials
   - Login with SQL injection attempt

3. **Account State Tests**
   - Login with locked account
   - Login with expired password

4. **Authorization Tests**
   - Protected resources require authentication

## Implementation Details

### Docker Container Configuration

Each LDAP server is configured as a Docker container using the Testcontainers library. The container configuration includes:

- Docker image and version
- Exposed ports
- Environment variables for configuration
- Wait strategy to ensure the server is ready before running tests
- Startup timeout to allow sufficient time for the server to start

### Spring Boot Configuration

Spring Boot is configured to use the Docker container for LDAP authentication using the `@DynamicPropertySource` annotation. The configuration includes:

- LDAP URL pointing to the Docker container
- Base DN for the LDAP directory
- Admin credentials for accessing the LDAP server
- User and group search bases and filters
- Disabling the embedded LDAP server

### Test Implementation

The tests are implemented using JUnit 5 and Spring Boot's testing framework. Each test class:

- Uses the `@Testcontainers` annotation to enable Testcontainers support
- Defines a Docker container for the specific LDAP server
- Configures Spring Boot to use the Docker container
- Implements test cases for various authentication scenarios

## Running the Tests

To run the tests for a specific LDAP server, use the following command:

```bash
./gradlew test --tests "org.example.app.<TestClassName>"
```

For example, to run the OpenLDAP tests:

```bash
./gradlew test --tests "org.example.app.OpenLdapIntegrationTests"
```

To run all LDAP tests:

```bash
./gradlew test --tests "org.example.app.*IntegrationTests"
```

## Notes and Considerations

1. **Resource Requirements**
   - Running Docker containers for LDAP servers can be resource-intensive
   - Some servers (like Active Directory and FreeIPA) may require significant memory and CPU
   - Consider running tests selectively or on a CI/CD server with sufficient resources

2. **Startup Time**
   - LDAP servers can take a long time to start, especially Active Directory and FreeIPA
   - Startup timeouts are configured accordingly, but may need adjustment based on your environment

3. **Windows Containers**
   - Active Directory tests require Windows containers, which are only supported on Windows hosts
   - Skip these tests when running on non-Windows platforms

4. **Test Data**
   - The tests assume specific user accounts and groups exist in the LDAP directory
   - In a real-world scenario, you would need to populate the LDAP directory with test data

5. **Security Considerations**
   - The Docker containers use default or simple passwords for testing
   - In a production environment, use strong passwords and secure connections (LDAPS)