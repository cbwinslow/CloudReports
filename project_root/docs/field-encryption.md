# Field-Level Encryption Implementation Guide

## Overview
The Enterprise Reporting System implements comprehensive field-level encryption to protect sensitive data at rest. This document details the encryption architecture, supported algorithms, key management, and integration guidelines.

## Encryption Architecture

### Multi-Layer Security
The field-level encryption system provides multiple layers of security:

1. **Field-Level Granularity**: Individual fields can be selectively encrypted
2. **Context-Aware Encryption**: Different encryption contexts for different data types
3. **Algorithm Selection**: Field-specific encryption algorithms
4. **Key Hierarchy**: Master key → Data encryption keys → Field encryption
5. **Key Rotation**: Automated key rotation with re-encryption
6. **Audit Trail**: Comprehensive logging of encryption operations

### Security Domains
The system organizes data into security domains for appropriate protection levels:

- **Public Data**: No encryption required
- **Internal Data**: Basic encryption for internal use
- **Confidential Data**: Strong encryption with key separation
- **Restricted Data**: Highest security with additional controls

## Supported Encryption Algorithms

### Symmetric Encryption
- **AES-GCM**: Authenticated encryption with 256-bit keys
- **ChaCha20-Poly1305**: High-performance authenticated encryption
- **AES-CBC**: Traditional block cipher with HMAC authentication

### Asymmetric Encryption
- **RSA-OAEP**: RSA encryption with optimal asymmetric encryption padding
- **ECDH**: Elliptic curve Diffie-Hellman key exchange
- **X25519**: Curve25519 key exchange for modern applications

### Key Derivation Functions
- **PBKDF2**: Password-based key derivation with configurable iterations
- **HKDF**: HMAC-based key derivation for modern applications
- **Scrypt**: Memory-hard key derivation for password protection
- **Argon2**: State-of-the-art password hashing and key derivation

## Key Management

### Key Hierarchy
The system implements a robust key hierarchy for security and manageability:

```text
Master Key (MK)
├── Data Encryption Key 1 (DEK-1)
│   ├── Field Key 1 (FK-1-1)
│   ├── Field Key 1 (FK-1-2)
│   └── ...
├── Data Encryption Key 2 (DEK-2)
│   ├── Field Key 2 (FK-2-1)
│   ├── Field Key 2 (FK-2-2)
│   └── ...
└── ...
```

### Master Key Sources
The system supports multiple master key sources:

1. **HashiCorp Vault**: Enterprise key management
2. **AWS KMS**: Cloud-based key management
3. **Azure Key Vault**: Microsoft cloud key management
4. **Google Cloud KMS**: Google cloud key management
5. **HSM Integration**: Hardware security modules
6. **Local Key Files**: Development/testing environments

### Key Rotation
Automated key rotation with comprehensive management:

- **Scheduled Rotation**: Configurable rotation intervals
- **On-Demand Rotation**: Manual triggering for security incidents
- **Graceful Transition**: Seamless transition with dual-key support
- **Archive Management**: Secure archiving of old keys
- **Re-encryption**: Automatic re-encryption of data with new keys

## Configuration Options

### Basic Configuration
```python
# Basic field encryption configuration
encryption_config = {
    "master_key": {
        "source": "vault",  # vault, kms, file, env
        "key_id": "reports-master-key",
        "rotation_days": 90
    },
    "algorithms": {
        "default": "AES-GCM",
        "password_fields": "PBKDF2-AES-GCM",
        "api_keys": "Fernet",
        "certificates": "RSA-OAEP"
    },
    "key_derivation": {
        "function": "PBKDF2",
        "iterations": 100000,
        "salt_length": 32
    },
    "fields": {
        "encrypted_by_default": [
            "password", "api_key", "secret", "token", 
            "private_key", "credentials", "ssh_key"
        ],
        "field_algorithms": {
            "password": "PBKDF2-AES-GCM",
            "api_key": "Fernet",
            "secret": "AES-GCM"
        }
    }
}
```

### Advanced Configuration
```python
# Advanced encryption configuration
advanced_config = {
    "performance": {
        "enable_caching": True,
        "cache_ttl_seconds": 3600,
        "batch_processing_threshold": 100,
        "parallel_encryption_threads": 4
    },
    "security": {
        "enable_key_wrapping": True,
        "require_authenticated_encryption": True,
        "enforce_minimum_entropy": True,
        "audit_all_operations": True
    },
    "compliance": {
        "enable_compliance_logging": True,
        "retention_days": 365,
        "export_encrypted_data": False,
        "tamper_detection": True
    },
    "failover": {
        "enable_failover_encryption": True,
        "fallback_to_plaintext": False,
        "graceful_degradation": True
    }
}
```

## Field-Level Encryption Patterns

### Pattern 1: Password Encryption
```python
# Password encryption with PBKDF2
password_config = {
    "field": "user_password",
    "algorithm": "PBKDF2-AES-GCM",
    "context": "user_authentication",
    "parameters": {
        "iterations": 150000,
        "salt_length": 32,
        "key_length": 32
    }
}

# Usage example
encrypted_password = encrypt_field(
    field_name="user_password",
    field_value="MySecurePassword123!",
    context="user_authentication",
    algorithm="PBKDF2-AES-GCM"
)
```

### Pattern 2: API Key Encryption
```python
# API key encryption with Fernet
api_key_config = {
    "field": "api_key",
    "algorithm": "Fernet",
    "context": "api_authentication",
    "parameters": {
        "ttl_seconds": 86400  # 24 hours
    }
}

# Usage example
encrypted_api_key = encrypt_field(
    field_name="api_key",
    field_value="sk-1234567890abcdef",
    context="api_authentication",
    algorithm="Fernet"
)
```

### Pattern 3: Certificate Encryption
```python
# Certificate encryption with RSA-OAEP
certificate_config = {
    "field": "private_key",
    "algorithm": "RSA-OAEP",
    "context": "tls_certificates",
    "parameters": {
        "padding_scheme": "OAEP",
        "hash_algorithm": "SHA-256"
    }
}

# Usage example
encrypted_private_key = encrypt_field(
    field_name="private_key",
    field_value=private_key_pem,
    context="tls_certificates",
    algorithm="RSA-OAEP"
)
```

## Integration with Data Stores

### Database Integration
The encryption system seamlessly integrates with various database systems:

#### PostgreSQL Integration
```sql
-- Encrypted field storage with metadata
CREATE TABLE encrypted_reports (
    id SERIAL PRIMARY KEY,
    report_type VARCHAR(50),
    hostname VARCHAR(255),
    encrypted_data BYTEA,
    encryption_context VARCHAR(100),
    encryption_algorithm VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index on non-encrypted metadata for query performance
CREATE INDEX idx_encrypted_reports_metadata 
ON encrypted_reports (report_type, hostname, created_at);
```

#### MongoDB Integration
```javascript
// Encrypted document structure
{
  "_id": ObjectId("..."),
  "report_type": "system",
  "hostname": "server01.example.com",
  "encrypted_fields": {
    "password": {
      "value": "base64_encoded_encrypted_data",
      "algorithm": "AES-GCM",
      "context": "system_credentials",
      "key_id": "key_12345"
    },
    "api_key": {
      "value": "base64_encoded_encrypted_data",
      "algorithm": "Fernet",
      "context": "external_integration",
      "key_id": "key_67890"
    }
  },
  "created_at": ISODate("2023-01-01T10:00:00Z"),
  "updated_at": ISODate("2023-01-01T10:00:00Z")
}
```

### File System Integration
For file-based storage, the system provides encrypted file handling:

```python
# Encrypted file operations
class EncryptedFileManager:
    def __init__(self, encryption_manager):
        self.encryption_manager = encryption_manager
    
    def write_encrypted_file(self, file_path: str, data: bytes, 
                           context: str = "file_storage") -> bool:
        """Write data to encrypted file"""
        try:
            # Encrypt data
            encrypted_data = self.encryption_manager.encrypt_field(
                "file_data", data, context=context
            )
            
            # Write to file
            with open(file_path, 'wb') as f:
                f.write(encrypted_data.encode('utf-8'))
            
            return True
        except Exception as e:
            logger.error(f"Error writing encrypted file {file_path}: {e}")
            return False
    
    def read_encrypted_file(self, file_path: str, 
                          context: str = "file_storage") -> Optional[bytes]:
        """Read and decrypt data from encrypted file"""
        try:
            # Read encrypted data
            with open(file_path, 'rb') as f:
                encrypted_data = f.read().decode('utf-8')
            
            # Decrypt data
            decrypted_data = self.encryption_manager.decrypt_field(
                "file_data", encrypted_data, context=context
            )
            
            return decrypted_data.encode('utf-8')
        except Exception as e:
            logger.error(f"Error reading encrypted file {file_path}: {e}")
            return None
```

## Performance Optimization

### Caching Strategy
The system implements intelligent caching for optimal performance:

```python
# Key caching configuration
key_cache_config = {
    "enable_caching": True,
    "cache_ttl_seconds": 3600,  # 1 hour
    "max_cache_size": 1000,
    "cache_eviction_policy": "LRU",  # Least Recently Used
    "prewarm_cache": True,  # Load frequently used keys at startup
    "cache_partitions": 16  # Sharding for concurrent access
}
```

### Batch Processing
For high-volume operations, batch processing optimizes throughput:

```python
# Batch encryption for bulk operations
def batch_encrypt_fields(self, field_data_list: List[Dict[str, Any]], 
                        context: str = "batch_operation") -> List[Dict[str, str]]:
    """Encrypt multiple fields in batch for improved performance"""
    try:
        encrypted_fields = []
        
        # Process in batches to optimize key derivation
        batch_size = self.config.batch_processing_threshold
        for i in range(0, len(field_data_list), batch_size):
            batch = field_data_list[i:i + batch_size]
            
            # Derive keys once per batch
            batch_key = self._get_cached_key(f"{context}_batch_{i//batch_size}")
            
            # Encrypt all fields in batch
            for field_data in batch:
                field_name = field_data['name']
                field_value = field_data['value']
                
                encrypted_value = self._encrypt_with_key(
                    field_name, field_value, batch_key
                )
                
                encrypted_fields.append({
                    'name': field_name,
                    'encrypted_value': encrypted_value
                })
        
        return encrypted_fields
        
    except Exception as e:
        logger.error(f"Error in batch encryption: {e}")
        raise FieldEncryptionError(f"Batch encryption failed: {str(e)}")
```

## Security Monitoring and Auditing

### Audit Trail
Comprehensive audit logging for all encryption operations:

```python
# Encryption audit log configuration
audit_config = {
    "log_encryption_operations": True,
    "log_decryption_operations": True,
    "log_key_operations": True,
    "log_performance_metrics": True,
    "log_security_events": True,
    "retention_days": 365,
    "export_format": "json",  # json, csv, syslog
    "real_time_alerts": True
}
```

### Security Event Detection
The system monitors for potential security issues:

```python
# Security monitoring rules
security_rules = {
    "failed_decryption_attempts": {
        "threshold": 5,
        "time_window_minutes": 10,
        "action": "alert_and_block"
    },
    "key_rotation_delays": {
        "threshold_days": 100,
        "action": "alert_administrator"
    },
    "unauthorized_access_attempts": {
        "threshold": 3,
        "time_window_minutes": 5,
        "action": "lock_account_temporarily"
    },
    "bulk_data_decryption": {
        "threshold_records": 1000,
        "time_window_minutes": 60,
        "action": "require_admin_approval"
    }
}
```

## Compliance Features

### Regulatory Compliance
The encryption system supports various compliance requirements:

#### GDPR Compliance
- **Data Minimization**: Encrypt only necessary sensitive fields
- **Right to Erasure**: Secure deletion of encrypted data
- **Data Portability**: Export of encrypted data in standard formats
- **Breach Notification**: Automated detection and reporting of potential breaches

#### HIPAA Compliance
- **Access Controls**: Role-based access to encrypted fields
- **Audit Logging**: Comprehensive logging of all access and modifications
- **Transmission Security**: Encryption of data in transit
- **Integrity Controls**: Tamper detection for encrypted data

#### SOX Compliance
- **Non-Repudiation**: Digital signatures for critical transactions
- **Access Logging**: Detailed audit trails for all user activities
- **Segregation of Duties**: Separation of encryption and decryption responsibilities
- **Retention Policies**: Automated enforcement of data retention periods

## Key Management Best Practices

### Key Storage Security
1. **Hardware Security Modules (HSMs)**: Use HSMs for master key storage
2. **Key Wrapping**: Wrap data encryption keys with master keys
3. **Key Rotation**: Implement regular automated key rotation
4. **Backup and Recovery**: Secure backup of encryption keys
5. **Access Control**: Restrict access to encryption keys

### Key Usage Guidelines
1. **Key Separation**: Use different keys for different data types
2. **Contextual Keys**: Derive keys based on usage context
3. **Key Lifecycles**: Implement complete key lifecycle management
4. **Key Versioning**: Maintain version history of encryption keys
5. **Key Archival**: Secure archival of old keys for data recovery

## Troubleshooting and Diagnostics

### Common Issues

#### Issue: Decryption Failures
**Symptoms**: 
- "Invalid MAC" errors
- "Key not found" errors
- "Corrupted data" errors

**Solutions**:
1. Verify key availability and accessibility
2. Check key rotation status
3. Validate data integrity
4. Review audit logs for recent changes

#### Issue: Performance Degradation
**Symptoms**:
- Slow encryption/decryption operations
- High CPU usage during cryptographic operations
- Delayed response times

**Solutions**:
1. Optimize key caching configuration
2. Implement batch processing for bulk operations
3. Review algorithm selection for performance requirements
4. Scale encryption processing across multiple threads/nodes

### Diagnostic Tools
The system includes comprehensive diagnostic capabilities:

```python
# Encryption diagnostics
diagnostic_config = {
    "enable_profiling": True,
    "profile_encryption_operations": True,
    "profile_key_derivation": True,
    "profile_cache_performance": True,
    "generate_performance_reports": True,
    "export_diagnostic_data": True
}
```

## API Integration

### Field Encryption API
The system provides a comprehensive API for field encryption operations:

```python
# Field encryption API endpoints
encryption_api_endpoints = {
    "encrypt_field": {
        "method": "POST",
        "path": "/api/v1/crypto/encrypt",
        "authentication": "api_key_required",
        "rate_limiting": "1000_requests_per_hour"
    },
    "decrypt_field": {
        "method": "POST",
        "path": "/api/v1/crypto/decrypt",
        "authentication": "api_key_required",
        "rate_limiting": "1000_requests_per_hour"
    },
    "encrypt_json": {
        "method": "POST",
        "path": "/api/v1/crypto/encrypt-json",
        "authentication": "api_key_required",
        "rate_limiting": "100_requests_per_hour"
    },
    "decrypt_json": {
        "method": "POST",
        "path": "/api/v1/crypto/decrypt-json",
        "authentication": "api_key_required",
        "rate_limiting": "100_requests_per_hour"
    },
    "key_status": {
        "method": "GET",
        "path": "/api/v1/crypto/key-status",
        "authentication": "admin_required",
        "rate_limiting": "10_requests_per_hour"
    },
    "rotate_keys": {
        "method": "POST",
        "path": "/api/v1/crypto/rotate-keys",
        "authentication": "admin_required",
        "rate_limiting": "1_request_per_day"
    }
}
```

### SDK Examples
The system provides SDKs for major programming languages:

```python
# Python SDK example
from reports.security.field_encryption import FieldEncryptionManager

# Initialize encryption manager
config = EncryptionConfig(master_key_source="vault")
encryption_manager = FieldEncryptionManager(config)

# Encrypt sensitive data
encrypted_password = encryption_manager.encrypt_field(
    "user_password",
    "MySecurePassword123!",
    context="user_authentication"
)

# Decrypt sensitive data
decrypted_password = encryption_manager.decrypt_field(
    "user_password",
    encrypted_password,
    context="user_authentication"
)
```

This comprehensive field-level encryption implementation provides enterprise-grade security while maintaining performance and usability for the Enterprise Reporting System.