"""
Field-Level Encryption for Enterprise Reporting System
"""

import os
import json
import base64
import hashlib
from typing import Optional, Dict, Any, Union, List
from dataclasses import dataclass
from datetime import datetime
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
import secrets

logger = logging.getLogger(__name__)

@dataclass
class EncryptionConfig:
    """Encryption Configuration"""
    # Master key configuration
    master_key_source: str = "vault"  # vault, kms, file, env
    master_key_id: Optional[str] = None
    master_key_path: Optional[str] = None
    
    # Encryption algorithms
    default_algorithm: str = "AES-GCM"  # AES-GCM, Fernet, RSA-OAEP
    key_derivation_function: str = "PBKDF2"  # PBKDF2, HKDF, Scrypt
    pbkdf2_iterations: int = 100000
    key_size_bits: int = 256
    
    # Field-specific encryption
    encrypted_fields: List[str] = None
    field_encryption_algorithms: Dict[str, str] = None
    
    # Key management
    key_rotation_days: int = 90
    key_cache_ttl_seconds: int = 3600
    enable_key_wrapping: bool = True
    
    # Performance settings
    enable_caching: bool = True
    cache_size_limit: int = 1000
    batch_encryption_threshold: int = 100  # Number of fields for batch processing

class FieldEncryptionError(Exception):
    """Custom exception for field encryption errors"""
    pass

class FieldEncryptionManager:
    """Manages field-level encryption for sensitive data"""
    
    def __init__(self, config: EncryptionConfig):
        self.config = config
        self.master_key = None
        self.key_cache = {}  # Cache for derived keys
        self.encryption_keys = {}  # Cache for data encryption keys
        self._load_master_key()
    
    def _load_master_key(self):
        """Load master encryption key based on configuration"""
        try:
            if self.config.master_key_source == "vault":
                self.master_key = self._load_from_vault()
            elif self.config.master_key_source == "kms":
                self.master_key = self._load_from_kms()
            elif self.config.master_key_source == "file":
                self.master_key = self._load_from_file()
            elif self.config.master_key_source == "env":
                self.master_key = self._load_from_environment()
            else:
                # Generate ephemeral key for testing
                self.master_key = Fernet.generate_key()
                logger.warning("Using ephemeral encryption key - NOT FOR PRODUCTION")
            
            if not self.master_key:
                raise FieldEncryptionError("Failed to load master encryption key")
                
        except Exception as e:
            logger.error(f"Error loading master key: {e}")
            raise FieldEncryptionError(f"Master key loading failed: {str(e)}")
    
    def _load_from_vault(self) -> Optional[bytes]:
        """Load master key from HashiCorp Vault"""
        try:
            # In a real implementation, this would connect to Vault
            # For demo, we'll return None to fall back to other methods
            vault_token = os.getenv("VAULT_TOKEN")
            vault_addr = os.getenv("VAULT_ADDR")
            
            if not vault_token or not vault_addr:
                logger.warning("Vault configuration not found")
                return None
            
            # Real implementation would use hvac or similar Vault client
            # client = hvac.Client(url=vault_addr, token=vault_token)
            # secret = client.secrets.transit.read_key(name=self.config.master_key_id)
            # return secret['data']['keys']['1']['public_key']
            
            logger.info("Vault integration stubbed for demo")
            return None
            
        except Exception as e:
            logger.error(f"Error loading key from Vault: {e}")
            return None
    
    def _load_from_kms(self) -> Optional[bytes]:
        """Load master key from AWS KMS or similar"""
        try:
            # In a real implementation, this would connect to KMS
            # For demo, we'll return None to fall back to other methods
            aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
            aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
            
            if not aws_access_key or not aws_secret_key:
                logger.warning("AWS KMS configuration not found")
                return None
            
            # Real implementation would use boto3
            # kms_client = boto3.client('kms', region_name='us-east-1')
            # response = kms_client.decrypt(CiphertextBlob=self.config.master_key_id)
            # return response['Plaintext']
            
            logger.info("KMS integration stubbed for demo")
            return None
            
        except Exception as e:
            logger.error(f"Error loading key from KMS: {e}")
            return None
    
    def _load_from_file(self) -> Optional[bytes]:
        """Load master key from local file"""
        try:
            if not self.config.master_key_path:
                logger.warning("No key file path configured")
                return None
            
            if not os.path.exists(self.config.master_key_path):
                logger.warning(f"Key file not found: {self.config.master_key_path}")
                return None
            
            # Read key file with proper permissions check
            file_stat = os.stat(self.config.master_key_path)
            if file_stat.st_mode & 0o777 != 0o600:
                logger.warning(f"Key file has insecure permissions: {oct(file_stat.st_mode & 0o777)}")
            
            with open(self.config.master_key_path, 'rb') as f:
                key_data = f.read()
            
            # Validate key format
            if len(key_data) not in [32, 44]:  # 256-bit key or base64 encoded
                raise FieldEncryptionError("Invalid key file format")
            
            return key_data
            
        except Exception as e:
            logger.error(f"Error loading key from file: {e}")
            return None
    
    def _load_from_environment(self) -> Optional[bytes]:
        """Load master key from environment variable"""
        try:
            key_base64 = os.getenv("ENCRYPTION_MASTER_KEY")
            if not key_base64:
                logger.warning("ENCRYPTION_MASTER_KEY environment variable not set")
                return None
            
            # Decode base64 key
            key_bytes = base64.b64decode(key_base64.encode('utf-8'))
            
            # Validate key size
            if len(key_bytes) != 32:
                raise FieldEncryptionError("Invalid key size - must be 256 bits")
            
            return key_bytes
            
        except Exception as e:
            logger.error(f"Error loading key from environment: {e}")
            return None
    
    def _derive_data_key(self, context: str = "") -> bytes:
        """Derive data encryption key from master key"""
        try:
            # Create context-specific salt
            context_bytes = context.encode('utf-8') if context else b""
            salt = hashlib.sha256(context_bytes).digest()
            
            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=crypto_hashes.SHA256(),
                length=self.config.key_size_bits // 8,
                salt=salt,
                iterations=self.config.pbkdf2_iterations,
            )
            
            derived_key = kdf.derive(self.master_key)
            return derived_key
            
        except Exception as e:
            logger.error(f"Error deriving data key: {e}")
            raise FieldEncryptionError(f"Key derivation failed: {str(e)}")
    
    def _get_cached_key(self, context: str = "") -> bytes:
        """Get cached or derive data encryption key"""
        try:
            if not self.config.enable_caching:
                return self._derive_data_key(context)
            
            cache_key = hashlib.sha256(context.encode('utf-8')).hexdigest()
            
            # Check cache
            if cache_key in self.key_cache:
                cached_key, timestamp = self.key_cache[cache_key]
                if (datetime.utcnow() - timestamp).total_seconds() < self.config.key_cache_ttl_seconds:
                    return cached_key
            
            # Derive new key
            derived_key = self._derive_data_key(context)
            
            # Cache key
            self.key_cache[cache_key] = (derived_key, datetime.utcnow())
            
            # Clean cache if too large
            if len(self.key_cache) > self.config.cache_size_limit:
                # Remove oldest entries
                oldest_keys = sorted(
                    [(k, v[1]) for k, v in self.key_cache.items()],
                    key=lambda x: x[1]
                )[:100]
                for key, _ in oldest_keys:
                    del self.key_cache[key]
            
            return derived_key
            
        except Exception as e:
            logger.error(f"Error getting cached key: {e}")
            # Fall back to non-cached derivation
            return self._derive_data_key(context)
    
    def encrypt_field(self, field_name: str, field_value: Union[str, bytes], 
                     context: str = "", algorithm: Optional[str] = None) -> str:
        """Encrypt a single field"""
        try:
            if field_value is None:
                return None
            
            # Convert to bytes if string
            if isinstance(field_value, str):
                data_bytes = field_value.encode('utf-8')
            else:
                data_bytes = field_value
            
            # Determine encryption algorithm
            if not algorithm:
                algorithm = self.config.field_encryption_algorithms.get(field_name, self.config.default_algorithm)
            
            # Get data encryption key
            data_key = self._get_cached_key(f"{context}:{field_name}")
            
            # Encrypt based on algorithm
            if algorithm == "AES-GCM":
                encrypted_data = self._encrypt_aes_gcm(data_bytes, data_key)
            elif algorithm == "Fernet":
                encrypted_data = self._encrypt_fernet(data_bytes, data_key)
            elif algorithm == "RSA-OAEP":
                encrypted_data = self._encrypt_rsa_oaep(data_bytes, data_key)
            else:
                raise FieldEncryptionError(f"Unsupported encryption algorithm: {algorithm}")
            
            # Return base64 encoded encrypted data
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error encrypting field {field_name}: {e}")
            raise FieldEncryptionError(f"Field encryption failed: {str(e)}")
    
    def decrypt_field(self, field_name: str, encrypted_value: str, 
                     context: str = "", algorithm: Optional[str] = None) -> str:
        """Decrypt a single field"""
        try:
            if encrypted_value is None:
                return None
            
            # Decode base64
            encrypted_bytes = base64.b64decode(encrypted_value.encode('utf-8'))
            
            # Determine encryption algorithm
            if not algorithm:
                algorithm = self.config.field_encryption_algorithms.get(field_name, self.config.default_algorithm)
            
            # Get data encryption key
            data_key = self._get_cached_key(f"{context}:{field_name}")
            
            # Decrypt based on algorithm
            if algorithm == "AES-GCM":
                decrypted_data = self._decrypt_aes_gcm(encrypted_bytes, data_key)
            elif algorithm == "Fernet":
                decrypted_data = self._decrypt_fernet(encrypted_bytes, data_key)
            elif algorithm == "RSA-OAEP":
                decrypted_data = self._decrypt_rsa_oaep(encrypted_bytes, data_key)
            else:
                raise FieldEncryptionError(f"Unsupported decryption algorithm: {algorithm}")
            
            # Return as string
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error decrypting field {field_name}: {e}")
            raise FieldEncryptionError(f"Field decryption failed: {str(e)}")
    
    def _encrypt_aes_gcm(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using AES-GCM"""
        try:
            # Generate nonce
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
            
            # Create AES-GCM cipher
            aesgcm = AESGCM(key[:32])  # Use first 32 bytes for 256-bit key
            
            # Encrypt data
            ciphertext = aesgcm.encrypt(nonce, data, None)
            
            # Prepend nonce to ciphertext
            return nonce + ciphertext
            
        except Exception as e:
            logger.error(f"AES-GCM encryption error: {e}")
            raise FieldEncryptionError(f"AES-GCM encryption failed: {str(e)}")
    
    def _decrypt_aes_gcm(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-GCM"""
        try:
            # Extract nonce (first 12 bytes)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Create AES-GCM cipher
            aesgcm = AESGCM(key[:32])  # Use first 32 bytes for 256-bit key
            
            # Decrypt data
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext
            
        except Exception as e:
            logger.error(f"AES-GCM decryption error: {e}")
            raise FieldEncryptionError(f"AES-GCM decryption failed: {str(e)}")
    
    def _encrypt_fernet(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using Fernet (symmetric encryption)"""
        try:
            # Derive Fernet key from provided key material
            # Fernet requires a 32-byte URL-safe base64-encoded key
            fernet_key = base64.urlsafe_b64encode(
                hashlib.sha256(key).digest()
            )
            
            # Create Fernet cipher
            cipher = Fernet(fernet_key)
            
            # Encrypt data
            return cipher.encrypt(data)
            
        except Exception as e:
            logger.error(f"Fernet encryption error: {e}")
            raise FieldEncryptionError(f"Fernet encryption failed: {str(e)}")
    
    def _decrypt_fernet(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using Fernet"""
        try:
            # Derive Fernet key from provided key material
            fernet_key = base64.urlsafe_b64encode(
                hashlib.sha256(key).digest()
            )
            
            # Create Fernet cipher
            cipher = Fernet(fernet_key)
            
            # Decrypt data
            return cipher.decrypt(encrypted_data)
            
        except Exception as e:
            logger.error(f"Fernet decryption error: {e}")
            raise FieldEncryptionError(f"Fernet decryption failed: {str(e)}")
    
    def _encrypt_rsa_oaep(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using RSA-OAEP (asymmetric encryption)"""
        try:
            # In a real implementation, this would use RSA public key
            # For demo, we'll simulate asymmetric encryption with symmetric
            
            # Generate ephemeral symmetric key
            sym_key = secrets.token_bytes(32)
            
            # Encrypt data with symmetric key (AES-GCM)
            encrypted_data = self._encrypt_aes_gcm(data, sym_key)
            
            # Encrypt symmetric key with RSA public key (simulated)
            # In real implementation: rsa_public_key.encrypt(sym_key, padding.OAEP(...))
            encrypted_sym_key = self._encrypt_aes_gcm(sym_key, key[:32])
            
            # Combine encrypted symmetric key and encrypted data
            # Format: [length of encrypted key (4 bytes)][encrypted key][encrypted data]
            import struct
            key_length = struct.pack('>I', len(encrypted_sym_key))
            
            return key_length + encrypted_sym_key + encrypted_data
            
        except Exception as e:
            logger.error(f"RSA-OAEP encryption error: {e}")
            raise FieldEncryptionError(f"RSA-OAEP encryption failed: {str(e)}")
    
    def _decrypt_rsa_oaep(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data using RSA-OAEP"""
        try:
            # Extract encrypted symmetric key
            import struct
            key_length = struct.unpack('>I', encrypted_data[:4])[0]
            encrypted_sym_key = encrypted_data[4:4+key_length]
            ciphertext = encrypted_data[4+key_length:]
            
            # Decrypt symmetric key with RSA private key (simulated)
            # In real implementation: rsa_private_key.decrypt(encrypted_sym_key, padding.OAEP(...))
            sym_key = self._decrypt_aes_gcm(encrypted_sym_key, key[:32])
            
            # Decrypt data with symmetric key
            return self._decrypt_aes_gcm(ciphertext, sym_key)
            
        except Exception as e:
            logger.error(f"RSA-OAEP decryption error: {e}")
            raise FieldEncryptionError(f"RSA-OAEP decryption failed: {str(e)}")
    
    def encrypt_json_object(self, obj: Dict[str, Any], context: str = "") -> Dict[str, Any]:
        """Encrypt all configured sensitive fields in a JSON object"""
        try:
            encrypted_obj = obj.copy()
            
            # Encrypt specified fields
            for field_name in self.config.encrypted_fields or []:
                if field_name in encrypted_obj:
                    field_value = encrypted_obj[field_name]
                    if field_value is not None:
                        encrypted_obj[field_name] = self.encrypt_field(
                            field_name, field_value, context
                        )
            
            return encrypted_obj
            
        except Exception as e:
            logger.error(f"Error encrypting JSON object: {e}")
            raise FieldEncryptionError(f"JSON object encryption failed: {str(e)}")
    
    def decrypt_json_object(self, encrypted_obj: Dict[str, Any], context: str = "") -> Dict[str, Any]:
        """Decrypt all configured sensitive fields in a JSON object"""
        try:
            decrypted_obj = encrypted_obj.copy()
            
            # Decrypt specified fields
            for field_name in self.config.encrypted_fields or []:
                if field_name in decrypted_obj:
                    encrypted_value = decrypted_obj[field_name]
                    if encrypted_value is not None:
                        decrypted_obj[field_name] = self.decrypt_field(
                            field_name, encrypted_value, context
                        )
            
            return decrypted_obj
            
        except Exception as e:
            logger.error(f"Error decrypting JSON object: {e}")
            raise FieldEncryptionError(f"JSON object decryption failed: {str(e)}")
    
    def generate_data_key(self, key_size: int = 32) -> bytes:
        """Generate a new data encryption key"""
        return secrets.token_bytes(key_size)
    
    def wrap_key(self, key: bytes, wrapping_key: bytes) -> bytes:
        """Wrap (encrypt) a key with another key"""
        return self._encrypt_aes_gcm(key, wrapping_key)
    
    def unwrap_key(self, wrapped_key: bytes, wrapping_key: bytes) -> bytes:
        """Unwrap (decrypt) a key with another key"""
        return self._decrypt_aes_gcm(wrapped_key, wrapping_key)
    
    def rotate_master_key(self) -> bool:
        """Rotate the master encryption key"""
        try:
            # Generate new master key
            new_master_key = Fernet.generate_key()
            
            # In a real implementation, this would:
            # 1. Generate new key in secure key management system
            # 2. Re-wrap all existing DEKs with new master key
            # 3. Update key references in database
            # 4. Archive old key for decryption of old data
            
            logger.info("Master key rotation initiated")
            return True
            
        except Exception as e:
            logger.error(f"Error rotating master key: {e}")
            return False

class EncryptedDataProcessor:
    """Processor for handling encrypted data in various formats"""
    
    def __init__(self, encryption_manager: FieldEncryptionManager):
        self.encryption_manager = encryption_manager
        self.logger = logging.getLogger(__name__)
    
    def process_report_data(self, report_data: Dict[str, Any], 
                           encrypt_fields: bool = True) -> Dict[str, Any]:
        """Process report data with optional field encryption"""
        try:
            if not encrypt_fields:
                return report_data
            
            # Fields that should always be encrypted
            sensitive_fields = [
                'password', 'api_key', 'secret', 'token', 'private_key',
                'credentials', 'connection_string', 'ssh_key'
            ]
            
            processed_data = {}
            
            for key, value in report_data.items():
                # Check if field should be encrypted
                if key in sensitive_fields or any(
                    sensitive_field in key.lower() 
                    for sensitive_field in sensitive_fields
                ):
                    # Encrypt the field
                    if isinstance(value, (str, bytes)):
                        try:
                            encrypted_value = self.encryption_manager.encrypt_field(
                                key, value, context="report_data"
                            )
                            processed_data[f"encrypted_{key}"] = encrypted_value
                            # Mark original field as encrypted
                            processed_data[key] = "[ENCRYPTED]"
                        except Exception as e:
                            self.logger.error(f"Failed to encrypt field {key}: {e}")
                            # Keep original value but log error
                            processed_data[key] = value
                    elif isinstance(value, dict):
                        # Recursively encrypt nested objects
                        processed_data[key] = self.process_report_data(
                            value, encrypt_fields=True
                        )
                    elif isinstance(value, list):
                        # Encrypt list items if they are strings
                        processed_data[key] = [
                            self.encryption_manager.encrypt_field(
                                f"{key}_{i}", item, context="report_data"
                            ) if isinstance(item, (str, bytes)) else item
                            for i, item in enumerate(value)
                        ]
                    else:
                        processed_data[key] = value
                else:
                    # Non-sensitive field, keep as-is
                    if isinstance(value, dict):
                        processed_data[key] = self.process_report_data(
                            value, encrypt_fields=False
                        )
                    elif isinstance(value, list) and value and isinstance(value[0], dict):
                        processed_data[key] = [
                            self.process_report_data(item, encrypt_fields=False)
                            for item in value
                        ]
                    else:
                        processed_data[key] = value
            
            return processed_data
            
        except Exception as e:
            self.logger.error(f"Error processing report data: {e}")
            raise FieldEncryptionError(f"Report data processing failed: {str(e)}")
    
    def restore_report_data(self, processed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Restore encrypted report data to original format"""
        try:
            restored_data = {}
            
            for key, value in processed_data.items():
                # Check if this is an encrypted field marker
                if key.startswith("encrypted_"):
                    original_key = key[10:]  # Remove "encrypted_" prefix
                    # The original field should have value "[ENCRYPTED]"
                    # We can't decrypt without the encrypted value and context
                    restored_data[original_key] = "[DECRYPTED_VALUE_NEEDED]"
                elif isinstance(value, dict):
                    restored_data[key] = self.restore_report_data(value)
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    restored_data[key] = [
                        self.restore_report_data(item) for item in value
                    ]
                else:
                    restored_data[key] = value
            
            return restored_data
            
        except Exception as e:
            self.logger.error(f"Error restoring report data: {e}")
            raise FieldEncryptionError(f"Report data restoration failed: {str(e)}")

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create encryption configuration
    config = EncryptionConfig(
        master_key_source="env",  # For demo, use environment variable
        encrypted_fields=[
            "password", "api_key", "secret", "token", 
            "private_key", "credentials", "ssh_key"
        ],
        field_encryption_algorithms={
            "password": "AES-GCM",
            "api_key": "Fernet",
            "secret": "AES-GCM"
        }
    )
    
    # Set demo encryption key in environment
    demo_key = Fernet.generate_key()
    os.environ["ENCRYPTION_MASTER_KEY"] = base64.b64encode(demo_key).decode('utf-8')
    
    print("🔐 Field-Level Encryption Demo")
    print("=" * 40)
    
    # Initialize encryption manager
    try:
        encryption_manager = FieldEncryptionManager(config)
        print("✅ Encryption manager initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize encryption manager: {e}")
        exit(1)
    
    # Test single field encryption
    print("\n1. Testing single field encryption...")
    try:
        original_data = "This is a secret message!"
        encrypted_data = encryption_manager.encrypt_field(
            "secret_message", 
            original_data, 
            context="demo"
        )
        print(f"✅ Original: {original_data}")
        print(f"✅ Encrypted: {encrypted_data[:20]}...")
        
        # Test decryption
        decrypted_data = encryption_manager.decrypt_field(
            "secret_message",
            encrypted_data,
            context="demo"
        )
        print(f"✅ Decrypted: {decrypted_data}")
        print(f"✅ Match: {original_data == decrypted_data}")
        
    except Exception as e:
        print(f"❌ Field encryption test failed: {e}")
    
    # Test JSON object encryption
    print("\n2. Testing JSON object encryption...")
    try:
        test_object = {
            "username": "john_doe",
            "password": "SuperSecretPassword123!",
            "api_key": "sk-1234567890abcdef",
            "email": "john@example.com",
            "nested_data": {
                "secret_token": "token_abcdef123456",
                "config": {
                    "db_password": "db_secret_password"
                }
            },
            "tags": ["confidential", "secret", "private"]
        }
        
        print("Original object:")
        print(json.dumps(test_object, indent=2))
        
        # Encrypt the object
        encrypted_processor = EncryptedDataProcessor(encryption_manager)
        encrypted_object = encrypted_processor.process_report_data(test_object)
        
        print("\nEncrypted object:")
        print(json.dumps(encrypted_object, indent=2))
        
        print("✅ JSON object encryption completed successfully")
        
    except Exception as e:
        print(f"❌ JSON object encryption test failed: {e}")
    
    # Test performance
    print("\n3. Testing performance with batch encryption...")
    try:
        import time
        
        # Create test data
        test_fields = [f"field_{i}" for i in range(100)]
        test_values = [f"value_{i}_sensitive_data" for i in range(100)]
        
        start_time = time.time()
        
        # Encrypt all fields
        encrypted_fields = []
        for field, value in zip(test_fields, test_values):
            encrypted_value = encryption_manager.encrypt_field(
                field, value, context="performance_test"
            )
            encrypted_fields.append((field, encrypted_value))
        
        encryption_time = time.time() - start_time
        
        # Decrypt all fields
        start_time = time.time()
        decrypted_fields = []
        for field, encrypted_value in encrypted_fields:
            decrypted_value = encryption_manager.decrypt_field(
                field, encrypted_value, context="performance_test"
            )
            decrypted_fields.append((field, decrypted_value))
        
        decryption_time = time.time() - start_time
        
        print(f"✅ Encrypted 100 fields in {encryption_time:.4f} seconds")
        print(f"✅ Decrypted 100 fields in {decryption_time:.4f} seconds")
        print(f"✅ Average encryption time: {encryption_time/100*1000:.2f} ms per field")
        print(f"✅ Average decryption time: {decryption_time/100*1000:.2f} ms per field")
        
    except Exception as e:
        print(f"❌ Performance test failed: {e}")
    
    print("\n🎯 Field-Level Encryption Demo Complete")
    print("This demonstrates the core functionality of field-level encryption.")
    print("In a production environment, this would integrate with:")
    print("  • Secure key management systems (Vault, KMS, HSM)")
    print("  • Database encryption at rest")
    print("  • Proper error handling and logging")
    print("  • Compliance monitoring and audit trails")
    print("  • Key rotation and certificate management")