"""
Authentication Service with MFA Integration
"""

import hashlib
import secrets
import jwt
import datetime
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
import logging
from ..security.mfa import MFAService

logger = logging.getLogger(__name__)

@dataclass
class User:
    """User data structure"""
    user_id: str
    username: str
    email: str
    password_hash: str
    salt: str
    is_active: bool = True
    mfa_enabled: bool = False
    created_at: datetime.datetime = None
    last_login: Optional[datetime.datetime] = None

class AuthenticationService:
    """Authentication service with MFA support"""
    
    def __init__(self, jwt_secret: str = None, mfa_service: MFAService = None):
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
        self.mfa_service = mfa_service or MFAService()
        self.users = {}  # In production, this would be a database
        self.sessions = {}  # In production, this would be Redis or database
        self.failed_attempts = {}  # Track failed login attempts
        self.max_failed_attempts = 5
        self.lockout_duration = 300  # 5 minutes in seconds
    
    def _hash_password(self, password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Create password hash using PBKDF2
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        
        return pwd_hash.hex(), salt
    
    def register_user(self, username: str, email: str, password: str) -> Dict[str, Any]:
        """Register a new user"""
        try:
            # Check if user already exists
            if username in self.users or email in [u.email for u in self.users.values()]:
                return {
                    'success': False,
                    'error': 'User already exists'
                }
            
            # Hash password
            password_hash, salt = self._hash_password(password)
            
            # Create user
            user_id = f"user_{secrets.token_urlsafe(16)}"
            user = User(
                user_id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                salt=salt,
                created_at=datetime.datetime.utcnow()
            )
            
            # Store user
            self.users[user_id] = user
            self.users[username] = user  # Also index by username
            
            logger.info(f"User registered: {username} ({user_id})")
            
            return {
                'success': True,
                'user_id': user_id,
                'message': 'User registered successfully'
            }
            
        except Exception as e:
            logger.error(f"Error registering user {username}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def authenticate_user(self, username: str, password: str, 
                         require_mfa: bool = True) -> Dict[str, Any]:
        """Authenticate user with password"""
        try:
            # Check if account is locked
            if self._is_account_locked(username):
                return {
                    'success': False,
                    'error': 'Account temporarily locked due to too many failed attempts'
                }
            
            # Find user
            user = self.users.get(username)
            if not user:
                self._record_failed_attempt(username)
                return {
                    'success': False,
                    'error': 'Invalid username or password'
                }
            
            # Check if user is active
            if not user.is_active:
                return {
                    'success': False,
                    'error': 'Account is deactivated'
                }
            
            # Verify password
            password_hash, _ = self._hash_password(password, user.salt)
            if password_hash != user.password_hash:
                self._record_failed_attempt(username)
                return {
                    'success': False,
                    'error': 'Invalid username or password'
                }
            
            # Reset failed attempts on successful login
            self._reset_failed_attempts(username)
            
            # Update last login
            user.last_login = datetime.datetime.utcnow()
            
            # Check if MFA is required/enabled
            if user.mfa_enabled and require_mfa:
                # Initiate MFA challenge
                challenge_result = self.mfa_service.initiate_mfa_challenge(
                    user.user_id, 
                    'totp'  # Default to TOTP, but could be configurable
                )
                
                if challenge_result['success']:
                    return {
                        'success': True,
                        'requires_mfa': True,
                        'challenge_id': challenge_result['challenge_id'],
                        'method': challenge_result['method'],
                        'message': 'MFA required - please complete second factor authentication'
                    }
                else:
                    # If MFA challenge fails, deny access
                    return {
                        'success': False,
                        'error': f'MFA challenge failed: {challenge_result["error"]}'
                    }
            else:
                # Generate JWT token for direct login
                token = self._generate_jwt_token(user)
                
                return {
                    'success': True,
                    'requires_mfa': False,
                    'token': token,
                    'user_id': user.user_id,
                    'username': user.username,
                    'message': 'Authentication successful'
                }
                
        except Exception as e:
            logger.error(f"Error authenticating user {username}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_mfa_challenge(self, challenge_id: str, mfa_response: str) -> Dict[str, Any]:
        """Verify MFA challenge response"""
        try:
            # Verify MFA challenge
            verification_result = self.mfa_service.verify_mfa_challenge(
                challenge_id, 
                mfa_response
            )
            
            if verification_result['success']:
                # Get user from challenge
                user_id = verification_result['user_id']
                user = self.users.get(user_id)
                
                if user:
                    # Generate JWT token
                    token = self._generate_jwt_token(user)
                    
                    return {
                        'success': True,
                        'token': token,
                        'user_id': user.user_id,
                        'username': user.username,
                        'message': 'MFA verification successful - authentication complete'
                    }
                else:
                    return {
                        'success': False,
                        'error': 'User not found after MFA verification'
                    }
            else:
                return {
                    'success': False,
                    'error': verification_result['error']
                }
                
        except Exception as e:
            logger.error(f"Error verifying MFA challenge {challenge_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_jwt_token(self, user: User) -> str:
        """Generate JWT token for authenticated user"""
        payload = {
            'user_id': user.user_id,
            'username': user.username,
            'email': user.email,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'aud': 'enterprise-reports-api'
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return user info"""
        try:
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=['HS256'],
                audience='enterprise-reports-api',
                options={'require': ['exp', 'iat', 'aud']}
            )
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidAudienceError:
            logger.warning("Invalid JWT audience")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None
    
    def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts"""
        if username in self.failed_attempts:
            attempts, last_attempt = self.failed_attempts[username]
            if attempts >= self.max_failed_attempts:
                # Check if lockout period has expired
                if (datetime.datetime.utcnow() - last_attempt).total_seconds() < self.lockout_duration:
                    return True
                else:
                    # Lockout period expired, reset attempts
                    del self.failed_attempts[username]
        return False
    
    def _record_failed_attempt(self, username: str):
        """Record failed login attempt"""
        now = datetime.datetime.utcnow()
        if username in self.failed_attempts:
            attempts, _ = self.failed_attempts[username]
            self.failed_attempts[username] = (attempts + 1, now)
        else:
            self.failed_attempts[username] = (1, now)
        
        logger.warning(f"Failed login attempt for user {username}")
    
    def _reset_failed_attempts(self, username: str):
        """Reset failed login attempts counter"""
        if username in self.failed_attempts:
            del self.failed_attempts[username]
    
    def enable_user_mfa(self, user_id: str) -> Dict[str, Any]:
        """Enable MFA for a user"""
        try:
            user = self.users.get(user_id)
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Enable MFA
            user.mfa_enabled = True
            
            # In a real implementation, this would trigger MFA enrollment
            # For now, we'll simulate successful enrollment
            
            logger.info(f"MFA enabled for user {user.username} ({user_id})")
            
            return {
                'success': True,
                'message': 'MFA enabled successfully'
            }
            
        except Exception as e:
            logger.error(f"Error enabling MFA for user {user_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def disable_user_mfa(self, user_id: str, admin_id: str = None) -> Dict[str, Any]:
        """Disable MFA for a user"""
        try:
            user = self.users.get(user_id)
            if not user:
                return {
                    'success': False,
                    'error': 'User not found'
                }
            
            # Disable MFA
            user.mfa_enabled = False
            
            # In a real implementation, this would also remove MFA enrollment data
            # await self.mfa_service.disable_user_mfa(user_id, admin_id)
            
            logger.info(f"MFA disabled for user {user.username} ({user_id}) by {admin_id or 'self'}")
            
            return {
                'success': True,
                'message': 'MFA disabled successfully'
            }
            
        except Exception as e:
            logger.error(f"Error disabling MFA for user {user_id}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

# Example usage
if __name__ == "__main__":
    # Initialize authentication service
    auth_service = AuthenticationService()
    
    print("🔐 Authentication Service Demo")
    print("=" * 40)
    
    # Register a demo user
    print("\n1. Registering demo user...")
    reg_result = auth_service.register_user(
        username="demo_user",
        email="demo@example.com",
        password="SecurePass123!"
    )
    
    if reg_result['success']:
        print("✅ User registered successfully")
        print(f"   User ID: {reg_result['user_id']}")
    else:
        print(f"❌ Registration failed: {reg_result['error']}")
    
    # Authenticate user
    print("\n2. Authenticating user...")
    auth_result = auth_service.authenticate_user(
        username="demo_user",
        password="SecurePass123!",
        require_mfa=False  # For demo, skip MFA
    )
    
    if auth_result['success']:
        print("✅ Authentication successful")
        print(f"   Token: {auth_result['token'][:20]}...")
        print(f"   MFA Required: {auth_result['requires_mfa']}")
    else:
        print(f"❌ Authentication failed: {auth_result['error']}")
    
    # Verify JWT token
    if auth_result['success'] and not auth_result['requires_mfa']:
        print("\n3. Verifying JWT token...")
        user_info = auth_service.verify_jwt_token(auth_result['token'])
        if user_info:
            print("✅ Token verification successful")
            print(f"   User: {user_info['username']}")
            print(f"   Expires: {user_info['exp']}")
        else:
            print("❌ Token verification failed")
    
    print("\n🎯 Authentication Service Demo Complete")
    print("This demonstrates password authentication and JWT token generation.")
    print("In a production environment, this would integrate with:")
    print("  • Database for user storage")
    print("  • Redis for session management")
    print("  • MFA service for second-factor authentication")
    print("  • Proper rate limiting and security measures")
    print("  • Audit logging for security events")