"""
Multi-Factor Authentication Implementation for Enterprise Reporting System
"""

import pyotp
import qrcode
import io
import base64
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import secrets
import hashlib
from dataclasses import dataclass
import json
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

logger = logging.getLogger(__name__)

@dataclass
class MFAFactors:
    """Represents different MFA factors"""
    totp_secret: Optional[str] = None
    backup_codes: Optional[list] = None
    webauthn_credential: Optional[Dict[str, Any]] = None
    sms_number: Optional[str] = None
    email: Optional[str] = None

class MFAProvider:
    """Multi-Factor Authentication Provider"""
    
    def __init__(self, encryption_key: Optional[bytes] = None):
        # Initialize encryption for storing MFA secrets
        if encryption_key:
            self.encryption_key = encryption_key
        else:
            # Generate or load encryption key
            key_file = "/tmp/mfa_encryption_key"
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(self.encryption_key)
        
        self.cipher_suite = Fernet(self.encryption_key)
    
    def generate_totp_secret(self, user_identifier: str) -> str:
        """Generate a TOTP secret for a user"""
        # Create a unique secret based on user identifier and random data
        combined = f"{user_identifier}{secrets.token_urlsafe(32)}".encode()
        secret = base64.b32encode(combined)[:32].decode()
        return secret.replace('=', '')  # Remove padding for cleaner secrets
    
    def generate_qr_code(self, secret: str, user_email: str, issuer: str = "Enterprise Reports") -> str:
        """Generate QR code for TOTP setup"""
        # Create TOTP URI
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            user_email,
            issuer_name=issuer
        )
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 string for easy transmission
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return img_str
    
    def verify_totp(self, secret: str, token: str, window: int = 1) -> bool:
        """Verify TOTP token"""
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=window)
        except Exception as e:
            logger.error(f"Error verifying TOTP token: {e}")
            return False
    
    def generate_backup_codes(self, count: int = 10) -> list:
        """Generate backup codes for MFA"""
        codes = []
        for _ in range(count):
            # Generate cryptographically secure backup code
            code = secrets.token_urlsafe(16)[:12].upper()
            codes.append(code)
        return codes
    
    def hash_backup_code(self, code: str) -> str:
        """Hash backup code for secure storage"""
        return hashlib.sha256(code.encode()).hexdigest()
    
    def verify_backup_code(self, user_id: str, code: str, stored_hashes: list) -> Tuple[bool, Optional[int]]:
        """Verify backup code and return index if valid"""
        code_hash = self.hash_backup_code(code)
        try:
            index = stored_hashes.index(code_hash)
            return True, index
        except ValueError:
            return False, None
    
    def generate_sms_otp(self) -> str:
        """Generate SMS OTP (6 digits)"""
        return str(secrets.randbelow(1000000)).zfill(6)
    
    def generate_email_otp(self) -> str:
        """Generate email OTP (8 characters)"""
        return secrets.token_urlsafe(8)[:8]
    
    def send_sms_otp(self, phone_number: str, otp: str) -> bool:
        """Send SMS OTP (placeholder implementation)"""
        # In a real implementation, this would integrate with an SMS provider
        # like Twilio, AWS SNS, or similar
        
        logger.info(f"Sending SMS OTP {otp} to {phone_number}")
        
        # Placeholder - in real implementation:
        # twilio_client.messages.create(
        #     body=f"Your verification code is: {otp}",
        #     from_=TWILIO_PHONE_NUMBER,
        #     to=phone_number
        # )
        
        return True  # Assume success for demo
    
    def send_email_otp(self, email: str, otp: str) -> bool:
        """Send email OTP (placeholder implementation)"""
        # In a real implementation, this would integrate with an email service
        # like SMTP, SendGrid, AWS SES, etc.
        
        logger.info(f"Sending email OTP {otp} to {email}")
        
        # Placeholder - in real implementation:
        # smtp_client.send_message(
        #     subject="Verification Code",
        #     body=f"Your verification code is: {otp}",
        #     to=email
        # )
        
        return True  # Assume success for demo

class MFAChallenge:
    """Represents an active MFA challenge"""
    
    def __init__(self, user_id: str, challenge_type: str, expires_at: datetime):
        self.user_id = user_id
        self.challenge_type = challenge_type
        self.challenge_id = secrets.token_urlsafe(32)
        self.created_at = datetime.utcnow()
        self.expires_at = expires_at
        self.attempts = 0
        self.max_attempts = 3

class MFAService:
    """Main MFA Service for the Enterprise Reporting System"""
    
    def __init__(self, db_manager=None):
        self.mfa_provider = MFAProvider()
        self.db_manager = db_manager
        self.active_challenges = {}  # In-memory store for active challenges
        self.logger = logging.getLogger(__name__)
    
    def enroll_user_totp(self, user_id: str, user_email: str) -> Dict[str, Any]:
        """Enroll user in TOTP-based MFA"""
        try:
            # Generate TOTP secret
            secret = self.mfa_provider.generate_totp_secret(user_id)
            
            # Generate QR code
            qr_code = self.mfa_provider.generate_qr_code(secret, user_email)
            
            # Generate backup codes
            backup_codes = self.mfa_provider.generate_backup_codes()
            
            # Store enrollment (in a real implementation, this would go to a database)
            enrollment_data = {
                'user_id': user_id,
                'totp_secret': secret,
                'backup_codes': [self.mfa_provider.hash_backup_code(code) for code in backup_codes],
                'enrolled_at': datetime.utcnow().isoformat(),
                'status': 'pending_verification'  # Will be activated after first successful verification
            }
            
            # In a real implementation:
            # await self.db_manager.store_mfa_enrollment(enrollment_data)
            
            return {
                'success': True,
                'secret': secret,
                'qr_code': qr_code,
                'backup_codes': backup_codes,
                'enrollment_data': enrollment_data
            }
            
        except Exception as e:
            self.logger.error(f"Error enrolling user {user_id} in TOTP: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_enrollment(self, user_id: str, totp_token: str) -> Dict[str, Any]:
        """Verify initial TOTP enrollment"""
        try:
            # In a real implementation, retrieve from database
            # enrollment_data = await self.db_manager.get_mfa_enrollment(user_id)
            
            # For demo, we'll simulate successful retrieval
            enrollment_data = {
                'totp_secret': 'SIMULATED_SECRET_FOR_DEMO',
                'status': 'pending_verification'
            }
            
            # Verify the token
            if self.mfa_provider.verify_totp(enrollment_data['totp_secret'], totp_token):
                # Activate MFA
                enrollment_data['status'] = 'active'
                enrollment_data['activated_at'] = datetime.utcnow().isoformat()
                
                # In a real implementation:
                # await self.db_manager.update_mfa_enrollment(user_id, enrollment_data)
                
                return {
                    'success': True,
                    'message': 'MFA enrollment verified and activated'
                }
            else:
                return {
                    'success': False,
                    'error': 'Invalid TOTP token'
                }
                
        except Exception as e:
            self.logger.error(f"Error verifying enrollment for user {user_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def initiate_mfa_challenge(self, user_id: str, preferred_method: str = 'totp') -> Dict[str, Any]:
        """Initiate MFA challenge for user login"""
        try:
            # In a real implementation, retrieve user's MFA settings
            # mfa_settings = await self.db_manager.get_user_mfa_settings(user_id)
            
            # For demo, we'll simulate
            mfa_settings = {
                'totp_secret': 'SIMULATED_SECRET',
                'backup_codes': ['HASH1', 'HASH2'],
                'sms_enabled': True,
                'sms_number': '+1XXXXXXXXXX',
                'email_enabled': True,
                'email': 'user@example.com'
            }
            
            challenge = MFAChallenge(
                user_id=user_id,
                challenge_type=preferred_method,
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            
            # Store challenge
            self.active_challenges[challenge.challenge_id] = challenge
            
            # Send challenge based on method
            if preferred_method == 'totp':
                # For TOTP, no additional action needed - user enters code from authenticator app
                return {
                    'success': True,
                    'challenge_id': challenge.challenge_id,
                    'method': 'totp',
                    'message': 'Enter code from your authenticator app'
                }
            
            elif preferred_method == 'backup':
                # For backup codes, no additional action needed
                return {
                    'success': True,
                    'challenge_id': challenge.challenge_id,
                    'method': 'backup',
                    'message': 'Enter one of your backup codes'
                }
            
            elif preferred_method == 'sms':
                # Generate and send SMS code
                otp = self.mfa_provider.generate_sms_otp()
                sent = self.mfa_provider.send_sms_otp(mfa_settings['sms_number'], otp)
                
                if sent:
                    # Store OTP hash for verification (in real implementation, in database)
                    # await self.db_manager.store_pending_challenge(challenge.challenge_id, {
                    #     'otp_hash': hashlib.sha256(otp.encode()).hexdigest(),
                    #     'expires_at': challenge.expires_at
                    # })
                    
                    return {
                        'success': True,
                        'challenge_id': challenge.challenge_id,
                        'method': 'sms',
                        'message': f'SMS code sent to {mfa_settings["sms_number"]}'
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Failed to send SMS code'
                    }
            
            elif preferred_method == 'email':
                # Generate and send email code
                otp = self.mfa_provider.generate_email_otp()
                sent = self.mfa_provider.send_email_otp(mfa_settings['email'], otp)
                
                if sent:
                    # Store OTP hash for verification (in real implementation, in database)
                    # await self.db_manager.store_pending_challenge(challenge.challenge_id, {
                    #     'otp_hash': hashlib.sha256(otp.encode()).hexdigest(),
                    #     'expires_at': challenge.expires_at
                    # })
                    
                    return {
                        'success': True,
                        'challenge_id': challenge.challenge_id,
                        'method': 'email',
                        'message': f'Email code sent to {mfa_settings["email"]}'
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Failed to send email code'
                    }
            
            else:
                return {
                    'success': False,
                    'error': f'Unsupported MFA method: {preferred_method}'
                }
                
        except Exception as e:
            self.logger.error(f"Error initiating MFA challenge for user {user_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_mfa_challenge(self, challenge_id: str, response: str) -> Dict[str, Any]:
        """Verify MFA challenge response"""
        try:
            # Check if challenge exists and is valid
            if challenge_id not in self.active_challenges:
                return {
                    'success': False,
                    'error': 'Invalid or expired challenge'
                }
            
            challenge = self.active_challenges[challenge_id]
            
            # Check if challenge is expired
            if datetime.utcnow() > challenge.expires_at:
                del self.active_challenges[challenge_id]
                return {
                    'success': False,
                    'error': 'Challenge expired'
                }
            
            # Check attempt limit
            if challenge.attempts >= challenge.max_attempts:
                del self.active_challenges[challenge_id]
                return {
                    'success': False,
                    'error': 'Too many failed attempts'
                }
            
            # Increment attempts
            challenge.attempts += 1
            
            # In a real implementation, verify based on challenge type
            # For demo, we'll simulate verification
            
            # Simulate verification success for demo purposes
            verification_result = True
            
            if verification_result:
                # Remove successful challenge
                del self.active_challenges[challenge_id]
                
                return {
                    'success': True,
                    'message': 'MFA verification successful',
                    'user_id': challenge.user_id
                }
            else:
                return {
                    'success': False,
                    'error': 'Invalid MFA response'
                }
                
        except Exception as e:
            self.logger.error(f"Error verifying MFA challenge {challenge_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def disable_user_mfa(self, user_id: str, admin_id: str = None) -> Dict[str, Any]:
        """Disable MFA for a user (admin function)"""
        try:
            # In a real implementation:
            # await self.db_manager.disable_user_mfa(user_id, admin_id)
            
            self.logger.info(f"MFA disabled for user {user_id} by {admin_id or 'self'}")
            
            return {
                'success': True,
                'message': 'MFA disabled successfully'
            }
            
        except Exception as e:
            self.logger.error(f"Error disabling MFA for user {user_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_user_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """Get MFA status for a user"""
        try:
            # In a real implementation:
            # mfa_settings = await self.db_manager.get_user_mfa_settings(user_id)
            
            # For demo, return simulated data
            return {
                'success': True,
                'mfa_enabled': True,
                'methods': ['totp', 'backup_codes'],
                'enrolled_at': datetime.utcnow().isoformat(),
                'last_used': (datetime.utcnow() - timedelta(hours=1)).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting MFA status for user {user_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

# Example usage and testing
if __name__ == "__main__":
    # Initialize MFA service
    mfa_service = MFAService()
    
    print("🔐 Multi-Factor Authentication Service Demo")
    print("=" * 50)
    
    # Demo user enrollment
    user_id = "demo_user_123"
    user_email = "demo@example.com"
    
    print(f"\n1. Enrolling user {user_id}...")
    enrollment_result = mfa_service.enroll_user_totp(user_id, user_email)
    
    if enrollment_result['success']:
        print("✅ TOTP enrollment initiated successfully")
        print(f"   Secret: {enrollment_result['secret']}")
        print(f"   Backup codes: {len(enrollment_result['backup_codes'])} codes generated")
        print("   QR code ready for authenticator app setup")
    else:
        print(f"❌ Enrollment failed: {enrollment_result['error']}")
    
    # Demo MFA challenge initiation
    print(f"\n2. Initiating MFA challenge...")
    challenge_result = mfa_service.initiate_mfa_challenge(user_id, 'totp')
    
    if challenge_result['success']:
        print("✅ MFA challenge initiated successfully")
        print(f"   Challenge ID: {challenge_result['challenge_id']}")
        print(f"   Method: {challenge_result['method']}")
    else:
        print(f"❌ Challenge initiation failed: {challenge_result['error']}")
    
    # Demo MFA status check
    print(f"\n3. Checking MFA status...")
    status_result = mfa_service.get_user_mfa_status(user_id)
    
    if status_result['success']:
        print("✅ MFA status retrieved successfully")
        print(f"   MFA Enabled: {status_result['mfa_enabled']}")
        print(f"   Methods: {', '.join(status_result['methods'])}")
    else:
        print(f"❌ Status check failed: {status_result['error']}")
    
    print("\n🎯 MFA Service Demo Complete")
    print("This demonstrates the core functionality of the MFA system.")
    print("In a production environment, this would integrate with:")
    print("  • User authentication system")
    print("  • Database for storing MFA configurations")
    print("  • SMS/email providers for code delivery")
    print("  • Proper error handling and logging")