# SAML Single Sign-On Implementation Guide

## Overview
The Enterprise Reporting System provides comprehensive SAML 2.0 Single Sign-On (SSO) integration for enterprise environments. This document explains the SAML implementation, configuration options, and integration procedures.

## SAML Implementation Features

### Supported SAML Profiles
- **Web Browser SSO Profile**: Primary SSO profile for web applications
- **Single Logout Profile**: Federated logout across all applications
- **Metadata Exchange**: Automatic metadata exchange with IDPs
- **Artifact Resolution Profile**: Optional artifact-based SSO flows

### Supported Bindings
- **HTTP Redirect Binding**: For AuthnRequest redirection
- **HTTP POST Binding**: For SAML responses and assertions
- **HTTP Artifact Binding**: For artifact-based exchanges
- **SOAP Binding**: For back-channel communications

### Security Features
- **Certificate-based Signatures**: RSA-SHA256 signatures for all SAML messages
- **Assertion Encryption**: Optional encryption of SAML assertions
- **Replay Attack Protection**: Unique IDs and timestamps prevent replay attacks
- **Man-in-the-Middle Protection**: TLS 1.2+ encryption for all communications
- **Signature Validation**: Comprehensive signature validation of all SAML messages

## SAML Configuration

### Basic Configuration
```python
# SAML Configuration Example
saml_config = {
    "idp": {
        "entity_id": "https://your-idp.com/saml",
        "sso_url": "https://your-idp.com/saml/sso",
        "slo_url": "https://your-idp.com/saml/slo",
        "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    },
    "sp": {
        "entity_id": "https://reports.yourcompany.com/saml/metadata",
        "acs_url": "https://reports.yourcompany.com/saml/acs",
        "slo_url": "https://reports.yourcompany.com/saml/slo"
    },
    "security": {
        "sign_authn_requests": True,
        "sign_assertions": True,
        "encrypt_assertions": False,
        "want_assertions_signed": True,
        "want_messages_signed": True
    }
}
```

### Advanced Configuration Options
```python
# Advanced SAML Configuration
advanced_saml_config = {
    "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "authn_context_class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    "attribute_map": {
        "email": ["mail", "emailAddress"],
        "first_name": ["givenName", "firstName"],
        "last_name": ["surname", "lastName"],
        "groups": ["memberOf", "groups"]
    },
    "session_lifetime": 480,  # 8 hours in minutes
    "clock_skew_tolerance": 300,  # 5 minutes tolerance for time sync issues
    "disable_signature_algorithm_check": False,
    "disable_digest_algorithm_check": False
}
```

## Integration with Popular IDPs

### Okta Integration
```python
# Okta-specific configuration
okta_config = {
    "idp": {
        "entity_id": "https://yourcompany.okta.com/saml",
        "sso_url": "https://yourcompany.okta.com/app/yourapp/sso/saml",
        "slo_url": "https://yourcompany.okta.com/app/yourapp/slo/saml",
        "cert": OKTA_CERT_PEM
    },
    "sp": {
        "entity_id": "https://reports.yourcompany.com/saml/metadata",
        "acs_url": "https://reports.yourcompany.com/saml/acs",
        "slo_url": "https://reports.yourcompany.com/saml/slo"
    },
    "attribute_map": {
        "email": ["user.email"],
        "first_name": ["user.firstName"],
        "last_name": ["user.lastName"],
        "groups": ["groups"]
    }
}
```

### Azure Active Directory Integration
```python
# Azure AD-specific configuration
azure_ad_config = {
    "idp": {
        "entity_id": "https://sts.windows.net/{tenant-id}/",
        "sso_url": "https://login.microsoftonline.com/{tenant-id}/saml2",
        "slo_url": "https://login.microsoftonline.com/{tenant-id}/saml2",
        "cert": AZURE_AD_CERT_PEM
    },
    "sp": {
        "entity_id": "https://reports.yourcompany.com/saml/metadata",
        "acs_url": "https://reports.yourcompany.com/saml/acs",
        "slo_url": "https://reports.yourcompany.com/saml/slo"
    },
    "attribute_map": {
        "email": ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
        "first_name": ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"],
        "last_name": ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"],
        "groups": ["http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"]
    }
}
```

### ADFS Integration
```python
# ADFS-specific configuration
adfs_config = {
    "idp": {
        "entity_id": "http://your-adfs-server/adfs/services/trust",
        "sso_url": "https://your-adfs-server/adfs/ls/",
        "slo_url": "https://your-adfs-server/adfs/ls/",
        "cert": ADFS_CERT_PEM
    },
    "sp": {
        "entity_id": "https://reports.yourcompany.com/saml/metadata",
        "acs_url": "https://reports.yourcompany.com/saml/acs",
        "slo_url": "https://reports.yourcompany.com/saml/slo"
    },
    "security": {
        "signature_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
    }
}
```

## SAML Metadata Exchange

### SP Metadata Generation
The Enterprise Reporting System automatically generates SAML metadata that can be consumed by Identity Providers:

```xml
<?xml version="1.0"?>
<EntityDescriptor 
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://reports.yourcompany.com/saml/metadata">
    
    <SPSSODescriptor 
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
        AuthnRequestsSigned="true"
        WantAssertionsSigned="true">
        
        <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>...</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        
        <KeyDescriptor use="encryption">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                <X509Data>
                    <X509Certificate>...</X509Certificate>
                </X509Data>
            </KeyInfo>
        </KeyDescriptor>
        
        <SingleLogoutService 
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            Location="https://reports.yourcompany.com/saml/slo"/>
            
        <SingleLogoutService 
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://reports.yourcompany.com/saml/slo"/>
            
        <AssertionConsumerService 
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="https://reports.yourcompany.com/saml/acs"
            index="1"/>
            
    </SPSSODescriptor>
    
</EntityDescriptor>
```

### IDP Metadata Consumption
The system can consume IDP metadata either:
1. **Manual Configuration**: Directly configuring IDP endpoints and certificates
2. **Automatic Download**: Periodically downloading and parsing IDP metadata
3. **Metadata Push**: Accepting metadata updates via API

## Attribute Mapping and Claims

### Default Attribute Mapping
The system supports comprehensive attribute mapping from SAML assertions to user profiles:

```python
# Default attribute mappings
DEFAULT_ATTRIBUTE_MAPPING = {
    "email": ["mail", "email", "emailAddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
    "username": ["uid", "sAMAccountName", "userPrincipalName"],
    "first_name": ["givenName", "firstName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"],
    "last_name": ["sn", "surname", "lastName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"],
    "display_name": ["displayName", "cn"],
    "groups": ["memberOf", "groups", "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"],
    "department": ["department", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality"],
    "title": ["title", "jobTitle"]
}
```

### Custom Attribute Mapping
Organizations can define custom attribute mappings to support specific requirements:

```python
# Custom attribute mapping example
CUSTOM_ATTRIBUTE_MAPPING = {
    "employee_id": ["employeeID", "empID", "http://schemas.mycompany.com/claims/employeeid"],
    "cost_center": ["costCenter", "departmentNumber"],
    "manager_email": ["manager", "supervisor"],
    "division": ["division", "businessUnit"]
}
```

## Session Management

### Session Lifecycle
The SAML implementation includes comprehensive session management:

1. **Session Creation**: Upon successful SAML authentication
2. **Session Validation**: Continuous validation of active sessions
3. **Session Extension**: Automatic extension for active users
4. **Session Termination**: Graceful termination on logout
5. **Session Cleanup**: Automatic cleanup of expired sessions

### Session Configuration Options
```python
SESSION_CONFIG = {
    "lifetime_minutes": 480,  # 8 hours
    "idle_timeout_minutes": 30,  # 30 minutes
    "max_sessions_per_user": 5,
    "renew_on_each_request": True,
    "secure_cookies": True,
    "http_only_cookies": True,
    "same_site_policy": "Strict"
}
```

## Single Logout (SLO) Support

### SLO Implementation
The system implements comprehensive Single Logout functionality:

1. **SP-Initiated Logout**: User initiates logout from the application
2. **IDP-Initiated Logout**: IDP initiates logout to all connected services
3. **Front-Channel Logout**: HTTP redirects for browser-based logout
4. **Back-Channel Logout**: SOAP-based logout notifications

### SLO Configuration
```python
SLO_CONFIG = {
    "enabled": True,
    "front_channel_supported": True,
    "back_channel_supported": True,
    "propagate_logout": True,
    "logout_confirmation_page": "/logout/confirm",
    "post_logout_redirect_url": "/login"
}
```

## Security Considerations

### Certificate Management
- **Automatic Certificate Rotation**: Support for automatic certificate updates
- **Certificate Pinning**: Optional certificate pinning for enhanced security
- **OCSP Validation**: Optional OCSP validation of certificates
- **CRL Checking**: Certificate revocation list checking

### Replay Attack Prevention
- **Unique Identifiers**: Cryptographically secure unique identifiers for all requests
- **Timestamp Validation**: Strict timestamp validation with configurable skew tolerance
- **One-Time Use**: Assertions and messages can only be used once
- **Session Tracking**: Comprehensive tracking of used identifiers

### Signature Validation
- **Algorithm Support**: Support for multiple signature algorithms (RSA-SHA256, RSA-SHA512, ECDSA)
- **Digest Algorithms**: Support for SHA-256, SHA-384, SHA-512 digests
- **Reference Validation**: Comprehensive validation of all signed references
- **Transform Validation**: Validation of applied XML transforms

## Monitoring and Auditing

### Audit Logging
Comprehensive audit logging for all SAML operations:

```python
AUDIT_LOG_CONFIG = {
    "log_authn_requests": True,
    "log_authn_responses": True,
    "log_assertions": True,
    "log_session_events": True,
    "log_logout_events": True,
    "log_errors": True,
    "log_warnings": True,
    "retention_days": 90
}
```

### Monitoring Metrics
The system exposes comprehensive metrics for monitoring:

- **Authentication Success Rate**: Percentage of successful authentications
- **Authentication Failure Rate**: Percentage of failed authentications
- **Average Response Time**: Average time for SAML operations
- **Session Count**: Current active session count
- **Error Rates**: Various error types and frequencies

## Troubleshooting and Debugging

### Common Issues and Solutions

#### Issue: "Invalid Signature" Error
**Causes:**
1. Certificate mismatch between IDP and SP
2. Clock skew between systems
3. Incorrect signature algorithm configuration

**Solutions:**
1. Verify certificates match between systems
2. Synchronize system clocks (NTP)
3. Check signature algorithm configuration

#### Issue: "Assertion Expired" Error
**Causes:**
1. Significant clock skew between systems
2. Assertion lifetime too short
3. Network latency causing processing delays

**Solutions:**
1. Configure NTP synchronization
2. Increase clock skew tolerance
3. Optimize network connectivity

#### Issue: "NameID Mismatch" Error
**Causes:**
1. NameID format mismatch between IDP and SP
2. Persistent NameID not supported by IDP
3. Incorrect NameID configuration

**Solutions:**
1. Configure matching NameID formats
2. Use transient NameID if persistent not supported
3. Verify NameID configuration in both systems

### Debugging Tools
The system includes comprehensive debugging capabilities:

```python
DEBUG_CONFIG = {
    "enable_debug_logging": False,
    "log_saml_messages": False,
    "log_xml_processing": False,
    "log_certificate_operations": False,
    "dump_raw_saml_responses": False,
    "enable_performance_profiling": False
}
```

## API Integration

### SAML Authentication Flow
The SSO integration follows the standard SAML Web Browser SSO profile:

1. **User Access**: User navigates to protected resource
2. **Authentication Check**: System checks for valid session
3. **SAML Redirect**: User redirected to IDP with AuthnRequest
4. **User Authentication**: User authenticates with IDP
5. **SAML Response**: IDP sends SAML Response to ACS endpoint
6. **Assertion Processing**: System processes SAML assertion
7. **Session Creation**: User session created
8. **Resource Access**: User granted access to requested resource

### REST API Endpoints
```python
# SAML-related API endpoints
SAML_API_ENDPOINTS = {
    "metadata": "/saml/metadata",           # GET - SP metadata
    "acs": "/saml/acs",                    # POST - Assertion Consumer Service
    "slo": "/saml/slo",                    # GET/POST - Single Logout
    "sso": "/saml/sso",                    # GET/POST - Single Sign-On
    "initiate": "/saml/initiate",          # GET - Initiate SSO flow
    "logout": "/saml/logout"               # POST - Initiate SLO flow
}
```

## Compliance and Standards

### Supported Standards
- **SAML 2.0 Core**: OASIS Standard for SAML 2.0
- **SAML 2.0 Bindings**: HTTP Redirect, HTTP POST, and SOAP bindings
- **SAML 2.0 Profiles**: Web Browser SSO and Single Logout profiles
- **XML Signature**: W3C XML Signature Syntax and Processing
- **XML Encryption**: W3C XML Encryption Syntax and Processing
- **X.509 Certificates**: RFC 5280 X.509 certificate handling

### Security Standards Compliance
- **TLS 1.2+**: Mandatory TLS for all communications
- **FIPS 140-2**: Cryptographic module compliance
- **OWASP**: Security recommendations from OWASP
- **NIST**: NIST cybersecurity framework alignment

This comprehensive SAML implementation provides enterprise-grade Single Sign-On capabilities while maintaining flexibility for various identity provider configurations and organizational requirements.