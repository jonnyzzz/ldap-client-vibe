# LDAP Configuration Guide for Users

## Introduction

This guide explains how to configure LDAP authentication for our application. LDAP (Lightweight Directory Access Protocol) allows you to use your existing directory service (like Active Directory or OpenLDAP) for user authentication.

## Table of Contents

1. [Basic Configuration](#basic-configuration)
2. [Connecting to Your LDAP Server](#connecting-to-your-ldap-server)
3. [User and Group Mapping](#user-and-group-mapping)
4. [Common LDAP Server Configurations](#common-ldap-server-configurations)
   - [Active Directory](#active-directory)
   - [OpenLDAP](#openldap)
   - [ApacheDS](#apacheds)
5. [Testing Your Configuration](#testing-your-configuration)
6. [Troubleshooting](#troubleshooting)
7. [Security Recommendations](#security-recommendations)

## Basic Configuration

To enable LDAP authentication, you need to configure the following properties in your `application.properties` file:

```properties
# LDAP Connection
spring.ldap.urls=ldap://your-ldap-server:389
spring.ldap.base=dc=example,dc=org
spring.ldap.username=cn=admin,dc=example,dc=org
spring.ldap.password=admin-password

# LDAP Authentication
spring.security.ldap.base-dn=dc=example,dc=org
spring.security.ldap.user-search-base=ou=people
spring.security.ldap.user-search-filter=(uid={0})
spring.security.ldap.group-search-base=ou=groups
spring.security.ldap.group-search-filter=(uniqueMember={0})
```

Replace the values with your actual LDAP server details.

## Connecting to Your LDAP Server

1. **LDAP URL**: Set the URL of your LDAP server
   ```properties
   spring.ldap.urls=ldap://your-ldap-server:389
   ```
   
   For secure LDAP (LDAPS), use:
   ```properties
   spring.ldap.urls=ldaps://your-ldap-server:636
   ```

2. **Base DN**: Set the base Distinguished Name for your LDAP directory
   ```properties
   spring.ldap.base=dc=example,dc=org
   ```
   
   This is typically your domain name converted to LDAP format (e.g., example.org becomes dc=example,dc=org)

3. **Admin Credentials**: Set the username and password for accessing your LDAP server
   ```properties
   spring.ldap.username=cn=admin,dc=example,dc=org
   spring.ldap.password=admin-password
   ```
   
   These credentials should have read access to user and group information.

## User and Group Mapping

Configure how users and groups are mapped from your LDAP directory:

1. **User Search Base**: The location in your LDAP directory where users are stored
   ```properties
   spring.security.ldap.user-search-base=ou=people
   ```

2. **User Search Filter**: The filter used to find users by their login name
   ```properties
   spring.security.ldap.user-search-filter=(uid={0})
   ```
   
   The `{0}` placeholder is replaced with the username entered during login.

3. **Group Search Base**: The location in your LDAP directory where groups are stored
   ```properties
   spring.security.ldap.group-search-base=ou=groups
   ```

4. **Group Search Filter**: The filter used to find groups a user belongs to
   ```properties
   spring.security.ldap.group-search-filter=(uniqueMember={0})
   ```
   
   The `{0}` placeholder is replaced with the user's DN.

## Common LDAP Server Configurations

### Active Directory

For Microsoft Active Directory, use these settings:

```properties
# Active Directory Connection
spring.ldap.urls=ldap://your-ad-server:389
spring.ldap.base=dc=company,dc=com
spring.ldap.username=company\\administrator
spring.ldap.password=admin-password

# Active Directory Authentication
spring.security.ldap.base-dn=dc=company,dc=com
spring.security.ldap.user-search-base=cn=Users
spring.security.ldap.user-search-filter=(sAMAccountName={0})
spring.security.ldap.group-search-base=cn=Groups
spring.security.ldap.group-search-filter=(member={0})
```

### OpenLDAP

For OpenLDAP, use these settings:

```properties
# OpenLDAP Connection
spring.ldap.urls=ldap://your-openldap-server:389
spring.ldap.base=dc=example,dc=org
spring.ldap.username=cn=admin,dc=example,dc=org
spring.ldap.password=admin-password

# OpenLDAP Authentication
spring.security.ldap.base-dn=dc=example,dc=org
spring.security.ldap.user-search-base=ou=people
spring.security.ldap.user-search-filter=(uid={0})
spring.security.ldap.group-search-base=ou=groups
spring.security.ldap.group-search-filter=(uniqueMember={0})
```

### ApacheDS

For ApacheDS, use these settings:

```properties
# ApacheDS Connection
spring.ldap.urls=ldap://your-apacheds-server:10389
spring.ldap.base=dc=example,dc=org
spring.ldap.username=uid=admin,ou=system
spring.ldap.password=admin-password

# ApacheDS Authentication
spring.security.ldap.base-dn=dc=example,dc=org
spring.security.ldap.user-search-base=ou=users
spring.security.ldap.user-search-filter=(uid={0})
spring.security.ldap.group-search-base=ou=groups
spring.security.ldap.group-search-filter=(member={0})
```

## Testing Your Configuration

After configuring your LDAP settings, you should test the connection:

1. Start the application
2. Try to log in with a valid LDAP username and password
3. Check the application logs for any LDAP-related errors

If you've enabled debug logging, you'll see detailed information about the LDAP authentication process:

```properties
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.ldap=DEBUG
```

## Troubleshooting

### Common Issues and Solutions

1. **Connection Refused**
   - **Issue**: Unable to connect to LDAP server
   - **Solution**: 
     - Verify the LDAP server URL and port
     - Check network connectivity and firewall settings
     - Ensure the LDAP server is running

2. **Invalid Credentials**
   - **Issue**: Admin credentials are rejected
   - **Solution**:
     - Verify the admin username and password
     - Check the format of the admin DN
     - Ensure the admin account has not expired or been locked

3. **User Not Found**
   - **Issue**: Valid users cannot log in
   - **Solution**:
     - Verify the user search base and filter
     - Check if the user exists in the specified location
     - Ensure the user attribute matches the search filter

4. **Group Membership Not Working**
   - **Issue**: User roles/permissions not correctly assigned
   - **Solution**:
     - Verify the group search base and filter
     - Check if the user is a member of the expected groups
     - Ensure the group membership attribute matches the search filter

### Checking LDAP Connectivity

You can use command-line tools to verify LDAP connectivity:

```bash
# For Linux/macOS
ldapsearch -H ldap://your-ldap-server:389 -D "cn=admin,dc=example,dc=org" -w admin-password -b "dc=example,dc=org" "(objectClass=*)"

# For Windows
ldapsearch -h your-ldap-server -p 389 -D "cn=admin,dc=example,dc=org" -w admin-password -b "dc=example,dc=org" "(objectClass=*)"
```

## Security Recommendations

1. **Use LDAPS (LDAP over SSL/TLS)**
   - Always use secure LDAP connections in production
   - Configure your LDAP server with a valid SSL certificate
   - Update your configuration to use `ldaps://` instead of `ldap://`

2. **Protect Admin Credentials**
   - Use a service account with minimal permissions
   - Store credentials securely (environment variables or a secure vault)
   - Regularly rotate the password

3. **Implement Connection Pooling**
   - For better performance, enable LDAP connection pooling:
     ```properties
     spring.ldap.pool.enabled=true
     spring.ldap.pool.max-active=8
     spring.ldap.pool.max-idle=8
     spring.ldap.pool.min-idle=0
     spring.ldap.pool.max-wait=-1ms
     ```

4. **Set Up Failover**
   - Configure multiple LDAP servers for high availability:
     ```properties
     spring.ldap.urls=ldap://primary-ldap:389 ldap://secondary-ldap:389
     ```

Remember to restart the application after making changes to the LDAP configuration.