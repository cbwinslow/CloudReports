#!/usr/bin/env python3

# Data Validation and Encryption Module for Enterprise Reporting System
# Handles data validation, sanitization, and encryption of collected reports

import json
import os
import hashlib
import hmac
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
from pathlib import Path
import re
from typing import Dict, Any, Union, Optional
import secrets

class DataValidator:
    """Validates and sanitizes collected report data"""
    
    def __init__(self, config=None):
        self.config = config or self.get_default_config()
        self.logger = logging.getLogger(__name__)
    
    def get_default_config(self):
        """Default validation configuration"""
        return {
            "required_fields": {
                "system": ["timestamp", "hostname"],
                "network": ["timestamp", "hostname"],
                "filesystem": ["timestamp", "hostname"],
                "error": ["timestamp", "hostname"],
                "log": ["timestamp", "hostname"]
            },
            "field_patterns": {
                "hostname": r"^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]$"
            },
            "field_sanitizers": {
                "hostname": self._sanitize_hostname,
                "command": self._sanitize_command,
                "path": self._sanitize_path
            },
            "max_field_lengths": {
                "hostname": 255,
                "command": 1000,
                "path": 4096
            }
        }
    
    def validate_report(self, report_data: Dict[str, Any], report_type: str) -> tuple[bool, list]:
        """Validate a report against configured rules"""
        errors = []
        
        # Check required fields
        required_fields = self.config.get("required_fields", {}).get(report_type, [])
        for field in required_fields:
            if field not in report_data:
                errors.append(f"Missing required field: {field}")
        
        # Validate and sanitize individual fields
        for field, value in report_data.items():
            if field in self.config.get("field_sanitizers", {}):
                # Sanitize field
                sanitized_value = self.config["field_sanitizers"][field](value)
                report_data[field] = sanitized_value
            
            # Apply length limits
            max_length = self.config.get("max_field_lengths", {}).get(field)
            if max_length and isinstance(value, str) and len(value) > max_length:
                errors.append(f"Field '{field}' exceeds maximum length of {max_length}")
        
        # Validate hostname pattern
        if "hostname" in report_data:
            hostname_pattern = self.config.get("field_patterns", {}).get("hostname")
            if hostname_pattern and not re.match(hostname_pattern, report_data["hostname"]):
                errors.append(f"Hostname '{report_data['hostname']}' does not match required pattern")
        
        return len(errors) == 0, errors
    
    def _sanitize_hostname(self, value):
        """Sanitize hostname field"""
        if not isinstance(value, str):
            return str(value)
        # Basic sanitization
        return re.sub(r'[^a-zA-Z0-9\-\.]', '', value)[:255]
    
    def _sanitize_command(self, value):
        """Sanitize command field"""
        if not isinstance(value, str):
            return str(value)
        # Remove potentially dangerous characters
        return re.sub(r'[;&|$`<>]', '', value)[:1000]
    
    def _sanitize_path(self, value):
        """Sanitize path field"""
        if not isinstance(value, str):
            return str(value)
        # Remove potentially dangerous characters
        return re.sub(r'[;&|$`<>]', '', value)[:4096]
    
    def validate_json_structure(self, data: Union[str, Dict]) -> tuple[bool, any]:
        """Validate JSON structure"""
        try:
            if isinstance(data, str):
                parsed_data = json.loads(data)
            else:
                parsed_data = data
            
            if not isinstance(parsed_data, dict):
                return False, "Data must be a JSON object"
            
            return True, parsed_data
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON: {e}"


class DataEncryptor:
    """Handles encryption and decryption of sensitive data"""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        self.logger = logging.getLogger(__name__)
        
        if encryption_key:
            self.key = encryption_key
        else:
            # Generate a key from environment or create a new one
            key_env = os.getenv('REPORTS_ENCRYPTION_KEY')
            if key_env:
                self.key = base64.urlsafe_b64decode(key_env)
            else:
                self.key = Fernet.generate_key()
                # Store the key in environment or a secure location
                os.environ['REPORTS_ENCRYPTION_KEY'] = base64.urlsafe_b64encode(self.key).decode()
        
        self.cipher = Fernet(self.key)
    
    def encrypt_data(self, data: Union[str, bytes, Dict]) -> str:
        """Encrypt data and return as base64 string"""
        try:
            if isinstance(data, dict):
                data = json.dumps(data)
            elif isinstance(data, bytes):
                data = data.decode('utf-8')
            
            encrypted_data = self.cipher.encrypt(data.encode('utf-8'))
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data from base64 string"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.cipher.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            raise
    
    def encrypt_file(self, input_path: str, output_path: str):
        """Encrypt a file"""
        try:
            with open(input_path, 'rb') as f:
                data = f.read()
            
            encrypted_data = self.cipher.encrypt(data)
            
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            self.logger.info(f"File encrypted: {input_path} -> {output_path}")
        except Exception as e:
            self.logger.error(f"File encryption error: {e}")
            raise
    
    def decrypt_file(self, input_path: str, output_path: str):
        """Decrypt a file"""
        try:
            with open(input_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.cipher.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"File decrypted: {input_path} -> {output_path}")
        except Exception as e:
            self.logger.error(f"File decryption error: {e}")
            raise
    
    def generate_key_from_password(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Generate encryption key from password"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key


class ReportIntegrity:
    """Handles data integrity and authentication"""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.secret_key = secret_key or os.getenv('REPORTS_INTEGRITY_SECRET', secrets.token_urlsafe(32))
    
    def generate_integrity_hash(self, data: Union[str, Dict]) -> str:
        """Generate integrity hash for data"""
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        else:
            data_str = str(data)
        
        return hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    
    def generate_signature(self, data: Union[str, Dict]) -> str:
        """Generate HMAC signature for data"""
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        else:
            data_str = str(data)
        
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            data_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def verify_signature(self, data: Union[str, Dict], signature: str) -> bool:
        """Verify HMAC signature for data"""
        expected_signature = self.generate_signature(data)
        return hmac.compare_digest(expected_signature, signature)


class DataProcessor:
    """Main class that combines validation, encryption, and integrity checking"""
    
    def __init__(self, config=None, encryption_key=None, integrity_secret=None):
        self.validator = DataValidator(config)
        self.encryptor = DataEncryptor(encryption_key)
        self.integrity = ReportIntegrity(integrity_secret)
        self.logger = logging.getLogger(__name__)
    
    def process_report(self, report_data: Dict[str, Any], report_type: str, 
                      encrypt: bool = False, add_integrity: bool = True) -> Dict[str, Any]:
        """Process a report with validation, encryption, and integrity"""
        # Validate the report
        is_valid, errors = self.validator.validate_report(report_data, report_type)
        if not is_valid:
            error_msg = f"Report validation failed: {'; '.join(errors)}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # Add integrity metadata if requested
        if add_integrity:
            report_data['integrity'] = {
                'hash': self.integrity.generate_integrity_hash(report_data),
                'signature': self.integrity.generate_signature(report_data),
                'processed_at': str(int(hash(time.time()) % 1e10))
            }
        
        # Encrypt sensitive fields if requested
        if encrypt:
            # For now, encrypt the entire report
            encrypted_report = self.encryptor.encrypt_data(report_data)
            return encrypted_report
        
        return report_data
    
    def save_report(self, report_data: Union[Dict[str, Any], str], 
                   output_path: str, encrypt: bool = False):
        """Save report to file with optional encryption"""
        if encrypt:
            self.encryptor.encrypt_file(output_path + '.tmp', output_path + '.enc')
            os.rename(output_path + '.enc', output_path)
        else:
            with open(output_path, 'w') as f:
                if isinstance(report_data, dict):
                    json.dump(report_data, f, indent=2)
                else:
                    f.write(report_data)
    
    def load_and_verify_report(self, input_path: str, decrypt: bool = False) -> Dict[str, Any]:
        """Load and verify report from file"""
        if decrypt:
            decrypted_path = input_path + '.tmp'
            self.encryptor.decrypt_file(input_path, decrypted_path)
            with open(decrypted_path, 'r') as f:
                report_data = json.load(f)
            os.remove(decrypted_path)
        else:
            with open(input_path, 'r') as f:
                report_data = json.load(f)
        
        # Verify integrity if present
        if 'integrity' in report_data:
            # Create a copy without the integrity field for verification
            temp_data = report_data.copy()
            integrity_info = temp_data.pop('integrity', None)
            
            expected_hash = self.integrity.generate_integrity_hash(temp_data)
            if integrity_info and integrity_info['hash'] != expected_hash:
                self.logger.warning(f"Integrity check failed for {input_path}")
            else:
                self.logger.debug(f"Integrity check passed for {input_path}")
        
        return report_data


# Example usage and testing
if __name__ == "__main__":
    import time
    
    # Initialize the processor
    processor = DataProcessor()
    
    # Example report data
    sample_report = {
        "timestamp": "2023-01-01T10:00:00Z",
        "hostname": "server1.example.com",
        "type": "system",
        "data": {
            "cpu": {"usage_percent": 15.2},
            "memory": {"usage_percent": 42.7}
        }
    }
    
    try:
        # Process the report
        processed_report = processor.process_report(sample_report, "system", encrypt=False)
        print("Report processed successfully")
        print(f"Integrity hash: {processed_report.get('integrity', {}).get('hash', 'N/A')}")
        
        # Save the report
        output_file = "/tmp/test_report.json"
        processor.save_report(processed_report, output_file)
        print(f"Report saved to {output_file}")
        
        # Load and verify the report
        loaded_report = processor.load_and_verify_report(output_file)
        print("Report loaded and verified successfully")
        
        # Test encryption
        encrypted_report = processor.process_report(sample_report, "system", encrypt=True)
        print(f"Report encrypted: {len(encrypted_report)} characters")
        
        # Save encrypted report
        encrypted_output = "/tmp/test_report_encrypted.json"
        with open(encrypted_output, 'w') as f:
            f.write(encrypted_report)
        print(f"Encrypted report saved to {encrypted_output}")
        
    except Exception as e:
        print(f"Error processing report: {e}")
        import traceback
        traceback.print_exc()