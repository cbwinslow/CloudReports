#!/usr/bin/env python3

# Credential Management System for Enterprise Reporting System
# Securely manages API keys, SSH keys, and other sensitive credentials

import os
import json
import hashlib
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import time
import logging
from typing import Dict, Any, Optional, List
import sqlite3
from contextlib import contextmanager
import re
from datetime import datetime, timedelta

class CredentialManager:
    """Secure credential management system"""
    
    def __init__(self, storage_path: str = "/home/cbwinslow/reports/credentials.db",
                 master_password: Optional[str] = None):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize master encryption key
        self.master_key = self._get_master_key(master_password)
        self.cipher = Fernet(self.master_key)
        
        # Initialize database
        self._init_database()
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _get_master_key(self, master_password: Optional[str]) -> bytes:
        """Get or create master encryption key"""
        key_file = Path("/home/cbwinslow/reports/.master_key")
        
        if key_file.exists():
            # Load existing key
            with open(key_file, 'rb') as f:
                salt = f.read(16)  # First 16 bytes are salt
                encrypted_key = f.read()
            
            # Derive key from password
            if not master_password:
                master_password = os.getenv('CREDENTIALS_MASTER_PASSWORD')
                if not master_password:
                    raise ValueError("Master password required to access credentials")
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            password_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            
            # Decrypt the master key
            cipher = Fernet(password_key)
            master_key = cipher.decrypt(encrypted_key)
        else:
            # Create new master key
            if not master_password:
                master_password = os.getenv('CREDENTIALS_MASTER_PASSWORD')
                if not master_password:
                    # Generate a secure password
                    master_password = secrets.token_urlsafe(32)
                    print(f"Generated master password: {master_password}")
                    print("IMPORTANT: Store this password securely. It's needed to access credentials.")
            
            # Generate salt and master key
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            
            password_key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            master_key = Fernet.generate_key()
            
            # Encrypt the master key with the password-derived key
            cipher = Fernet(password_key)
            encrypted_master_key = cipher.encrypt(master_key)
            
            # Save salt + encrypted key
            with open(key_file, 'wb') as f:
                f.write(salt + encrypted_master_key)
            
            # Set restrictive permissions
            os.chmod(key_file, 0o600)
        
        return master_key
    
    def _init_database(self):
        """Initialize the credentials database"""
        with sqlite3.connect(self.storage_path) as conn:
            cursor = conn.cursor()
            
            # Create credentials table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    credential_type TEXT NOT NULL,
                    encrypted_value TEXT NOT NULL,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    active BOOLEAN DEFAULT TRUE,
                    metadata TEXT  -- JSON metadata
                )
            ''')
            
            # Create index for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_name ON credentials(name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_type ON credentials(credential_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_active ON credentials(active)')
            
            conn.commit()
    
    def _encrypt_value(self, value: str) -> str:
        """Encrypt a credential value"""
        encrypted_bytes = self.cipher.encrypt(value.encode('utf-8'))
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt a credential value"""
        encrypted_bytes = base64.b64decode(encrypted_value.encode('utf-8'))
        decrypted_bytes = self.cipher.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    
    def store_credential(self, name: str, credential_type: str, value: str,
                        description: str = "", expires_at: Optional[datetime] = None,
                        metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Store a credential securely"""
        try:
            encrypted_value = self._encrypt_value(value)
            
            with sqlite3.connect(self.storage_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO credentials 
                    (name, credential_type, encrypted_value, description, expires_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    name, credential_type, encrypted_value, 
                    description, expires_at.isoformat() if expires_at else None,
                    json.dumps(metadata) if metadata else None
                ))
                
                conn.commit()
                self.logger.info(f"Credential stored: {name} ({credential_type})")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to store credential {name}: {e}")
            return False
    
    def retrieve_credential(self, name: str) -> Optional[str]:
        """Retrieve and decrypt a credential by name"""
        try:
            with sqlite3.connect(self.storage_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM credentials 
                    WHERE name = ? AND active = TRUE
                ''', (name,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Check if credential has expired
                if row['expires_at']:
                    expires_at = datetime.fromisoformat(row['expires_at'])
                    if datetime.utcnow() > expires_at:
                        self.logger.warning(f"Credential {name} has expired")
                        return None
                
                return self._decrypt_value(row['encrypted_value'])
                
        except Exception as e:
            self.logger.error(f"Failed to retrieve credential {name}: {e}")
            return None
    
    def delete_credential(self, name: str) -> bool:
        """Delete a credential"""
        try:
            with sqlite3.connect(self.storage_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM credentials WHERE name = ?', (name,))
                affected = cursor.rowcount
                conn.commit()
                
                if affected > 0:
                    self.logger.info(f"Credential deleted: {name}")
                    return True
                else:
                    self.logger.warning(f"Credential not found: {name}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Failed to delete credential {name}: {e}")
            return False
    
    def list_credentials(self, credential_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all credentials (with optional type filter)"""
        try:
            with sqlite3.connect(self.storage_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT name, credential_type, description, created_at, expires_at, active FROM credentials WHERE 1=1'
                params = []
                
                if credential_type:
                    query += ' AND credential_type = ?'
                    params.append(credential_type)
                
                query += ' ORDER BY created_at DESC'
                cursor.execute(query, params)
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            self.logger.error(f"Failed to list credentials: {e}")
            return []
    
    def update_credential(self, name: str, new_value: Optional[str] = None,
                         new_description: Optional[str] = None,
                         new_expires_at: Optional[datetime] = None,
                         new_metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Update a credential"""
        try:
            # First get the existing credential
            with sqlite3.connect(self.storage_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM credentials WHERE name = ?', (name,))
                row = cursor.fetchone()
                
                if not row:
                    self.logger.error(f"Credential not found: {name}")
                    return False
                
                # Prepare update values
                if new_value is not None:
                    encrypted_value = self._encrypt_value(new_value)
                else:
                    encrypted_value = row['encrypted_value']
                
                description = new_description if new_description is not None else row['description']
                expires_at = new_expires_at.isoformat() if new_expires_at else row['expires_at']
                metadata = json.dumps(new_metadata) if new_metadata is not None else row['metadata']
                
                cursor.execute('''
                    UPDATE credentials
                    SET encrypted_value = ?, description = ?, expires_at = ?, metadata = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE name = ?
                ''', (encrypted_value, description, expires_at, metadata, name))
                
                conn.commit()
                self.logger.info(f"Credential updated: {name}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to update credential {name}: {e}")
            return False
    
    def generate_api_key(self, name: str, description: str = "") -> str:
        """Generate and store a new API key"""
        api_key = f"rep_{secrets.token_urlsafe(32)}"
        
        if self.store_credential(
            name=name,
            credential_type="api_key",
            value=api_key,
            description=description,
            metadata={"created_by": "system", "purpose": "api_authentication"}
        ):
            return api_key
        else:
            raise Exception("Failed to generate API key")
    
    def validate_api_key(self, api_key: str) -> Optional[str]:
        """Validate an API key and return its name if valid"""
        credentials = self.list_credentials("api_key")
        
        for cred in credentials:
            stored_key = self.retrieve_credential(cred['name'])
            if stored_key and stored_key == api_key:
                return cred['name']
        
        return None
    
    def store_ssh_key(self, name: str, private_key: str, public_key: str = "",
                     description: str = "") -> bool:
        """Store SSH key pair"""
        metadata = {"public_key": public_key} if public_key else None
        
        return self.store_credential(
            name=name,
            credential_type="ssh_key",
            value=private_key,
            description=description,
            metadata=metadata
        )
    
    def store_database_credentials(self, name: str, host: str, username: str,
                                 password: str, database: str = "",
                                 port: int = 5432) -> bool:
        """Store database credentials"""
        metadata = {
            "host": host,
            "port": port,
            "database": database
        }
        
        return self.store_credential(
            name=name,
            credential_type="database",
            value=password,
            description=f"Database credentials for {host}/{database}",
            metadata=metadata
        )
    
    def get_database_connection_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get database connection information"""
        with sqlite3.connect(self.storage_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM credentials 
                WHERE name = ? AND credential_type = ? AND active = TRUE
            ''', (name, "database"))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            # Check expiration
            if row['expires_at']:
                expires_at = datetime.fromisoformat(row['expires_at'])
                if datetime.utcnow() > expires_at:
                    return None
            
            metadata = json.loads(row['metadata']) if row['metadata'] else {}
            
            return {
                "host": metadata.get("host"),
                "port": metadata.get("port", 5432),
                "database": metadata.get("database"),
                "username": name,  # Using credential name as username
                "password": self._decrypt_value(row['encrypted_value'])
            }
    
    def cleanup_expired_credentials(self) -> int:
        """Remove expired credentials"""
        try:
            cutoff_time = datetime.utcnow().isoformat()
            
            with sqlite3.connect(self.storage_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    DELETE FROM credentials 
                    WHERE expires_at IS NOT NULL 
                    AND expires_at < ?
                ''', (cutoff_time,))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                if deleted_count > 0:
                    self.logger.info(f"Cleaned up {deleted_count} expired credentials")
                
                return deleted_count
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup expired credentials: {e}")
            return 0
    
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Change the master password"""
        try:
            # Verify old password by attempting to decrypt the master key
            key_file = Path("/home/cbwinslow/reports/.master_key")
            with open(key_file, 'rb') as f:
                salt = f.read(16)
                encrypted_key = f.read()
            
            # Derive key from old password
            old_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            old_password_key = base64.urlsafe_b64encode(
                old_kdf.derive(old_password.encode())
            )
            
            # Decrypt master key with old password
            old_cipher = Fernet(old_password_key)
            master_key = old_cipher.decrypt(encrypted_key)
            
            # Derive key from new password
            new_kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            new_password_key = base64.urlsafe_b64encode(
                new_kdf.derive(new_password.encode())
            )
            
            # Encrypt master key with new password
            new_cipher = Fernet(new_password_key)
            new_encrypted_master_key = new_cipher.encrypt(master_key)
            
            # Save the new encrypted key
            with open(key_file, 'wb') as f:
                f.write(salt + new_encrypted_master_key)
            
            self.logger.info("Master password changed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to change master password: {e}")
            return False
    
    def export_credentials(self, export_path: str, 
                          include_values: bool = False) -> bool:
        """Export credentials (optionally including values)"""
        try:
            with sqlite3.connect(self.storage_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM credentials')
                rows = cursor.fetchall()
                
                export_data = []
                for row in rows:
                    item = {
                        "name": row["name"],
                        "credential_type": row["credential_type"],
                        "description": row["description"],
                        "created_at": row["created_at"],
                        "updated_at": row["updated_at"],
                        "expires_at": row["expires_at"],
                        "active": row["active"],
                        "metadata": json.loads(row["metadata"]) if row["metadata"] else None
                    }
                    
                    if include_values:
                        # Only export values if explicitly requested
                        item["value"] = self._decrypt_value(row["encrypted_value"])
                    
                    export_data.append(item)
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Credentials exported to {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export credentials: {e}")
            return False


class CredentialValidator:
    """Validates credentials and enforces security policies"""
    
    @staticmethod
    def validate_api_key_format(api_key: str) -> bool:
        """Validate API key format"""
        # API keys should be at least 32 characters and contain alphanumeric + some special chars
        return len(api_key) >= 32 and re.match(r'^[a-zA-Z0-9_\-]+$', api_key) is not None
    
    @staticmethod
    def validate_ssh_key_format(private_key: str) -> bool:
        """Basic validation for SSH private keys"""
        return private_key.startswith('-----BEGIN') and '-----END' in private_key
    
    @staticmethod
    def validate_password_strength(password: str) -> bool:
        """Validate password strength"""
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):  # Has uppercase
            return False
        if not re.search(r'[a-z]', password):  # Has lowercase
            return False
        if not re.search(r'\d', password):     # Has digit
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):  # Has special char
            return False
        return True


class CredentialProvider:
    """Provides credentials to other parts of the system"""
    
    def __init__(self, credential_manager: CredentialManager):
        self.cred_manager = credential_manager
    
    def get_api_key(self, name: str) -> Optional[str]:
        """Get an API key by name"""
        return self.cred_manager.retrieve_credential(name)
    
    def get_ssh_key(self, name: str) -> Optional[Dict[str, str]]:
        """Get SSH key information"""
        private_key = self.cred_manager.retrieve_credential(name)
        if not private_key:
            return None
        
        # Get metadata for the public key
        with sqlite3.connect(self.cred_manager.storage_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute('SELECT metadata FROM credentials WHERE name = ?', (name,))
            row = cursor.fetchone()
            
            if row and row['metadata']:
                metadata = json.loads(row['metadata'])
                public_key = metadata.get('public_key', '')
            else:
                public_key = ''
        
        return {
            "private_key": private_key,
            "public_key": public_key
        }
    
    def get_database_credentials(self, name: str) -> Optional[Dict[str, Any]]:
        """Get database connection information"""
        return self.cred_manager.get_database_connection_info(name)


# Example usage
if __name__ == "__main__":
    import tempfile
    
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Initialize credential manager
        cred_manager = CredentialManager(
            storage_path=temp_path / "test_credentials.db",
            master_password="test_master_password_12345"
        )
        
        # Store some credentials
        print("Storing credentials...")
        
        # API key
        api_key = cred_manager.generate_api_key(
            name="test_api_key",
            description="Test API key for development"
        )
        print(f"Generated API key: {api_key}")
        
        # SSH key
        ssh_private = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACB8zJ2X6ZKQY7l5Z6f8J7m9q8p4n3v2x1c0z9y8w7v6u5t
-----END OPENSSH PRIVATE KEY-----"""
        
        cred_manager.store_ssh_key(
            name="test_ssh_key",
            private_key=ssh_private,
            description="Test SSH key"
        )
        
        # Database credentials
        cred_manager.store_database_credentials(
            name="test_db_user",
            host="localhost",
            username="testuser",
            password="secure_password_123",
            database="testdb"
        )
        
        print("Credentials stored successfully")
        
        # List credentials
        print("\nStored credentials:")
        creds = cred_manager.list_credentials()
        for cred in creds:
            print(f"  - {cred['name']} ({cred['credential_type']}): {cred['description']}")
        
        # Retrieve credentials
        print(f"\nRetrieved API key: {cred_manager.retrieve_credential('test_api_key')}")
        
        ssh_info = cred_manager.retrieve_credential('test_ssh_key')
        print(f"Retrieved SSH key: {'Found' if ssh_info else 'Not found'}")
        
        db_info = cred_manager.get_database_connection_info('test_db_user')
        print(f"Database connection info: {db_info}")
        
        # Validate API key
        validator = CredentialValidator()
        print(f"\nAPI key validation: {validator.validate_api_key_format(api_key)}")
        
        # Test credential provider
        provider = CredentialProvider(cred_manager)
        provided_key = provider.get_api_key('test_api_key')
        print(f"Provider retrieved API key: {provided_key == api_key}")
        
        # Test API key validation
        key_name = cred_manager.validate_api_key(api_key)
        print(f"Validated API key name: {key_name}")
        
        print("\nCredential management system working correctly!")