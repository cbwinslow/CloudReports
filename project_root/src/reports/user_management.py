"""
User Management System Implementation
"""

import os
import json
import hashlib
import secrets
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import sqlite3
from contextlib import contextmanager
import logging
from enum import Enum
import jwt
from passlib.hash import argon2, bcrypt

logger = logging.getLogger(__name__)

class UserRole(Enum):
    """User roles in the system"""
    ADMIN = "admin"
    REPORT_VIEWER = "report_viewer"
    SYSTEM_ADMIN = "system_admin"
    AUDITOR = "auditor"
    DEVELOPER = "developer"
    GUEST = "guest"

class Permission(Enum):
    """System permissions"""
    # System-level permissions
    SYSTEM_ADMIN = "system.admin"
    SYSTEM_READ = "system.read"
    SYSTEM_WRITE = "system.write"
    
    # Report permissions
    REPORT_CREATE = "report.create"
    REPORT_READ = "report.read"
    REPORT_UPDATE = "report.update"
    REPORT_DELETE = "report.delete"
    REPORT_EXPORT = "report.export"
    REPORT_IMPORT = "report.import"
    
    # User management permissions
    USER_CREATE = "user.create"
    USER_READ = "user.read"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"
    USER_MANAGE_ROLES = "user.manage_roles"
    
    # Configuration permissions
    CONFIG_READ = "config.read"
    CONFIG_UPDATE = "config.update"
    CONFIG_MANAGE = "config.manage"
    
    # Security permissions
    SECURITY_AUDIT = "security.audit"
    SECURITY_MONITOR = "security.monitor"
    SECURITY_ALERT = "security.alert"
    
    # API permissions
    API_ACCESS = "api.access"
    API_ADMIN = "api.admin"
    
    # Dashboard permissions
    DASHBOARD_VIEW = "dashboard.view"
    DASHBOARD_EDIT = "dashboard.edit"
    DASHBOARD_ADMIN = "dashboard.admin"
    
    # Alert permissions
    ALERT_VIEW = "alert.view"
    ALERT_MANAGE = "alert.manage"
    ALERT_CONFIGURE = "alert.configure"
    
    # Integration permissions
    INTEGRATION_READ = "integration.read"
    INTEGRATION_CONFIGURE = "integration.configure"
    INTEGRATION_MANAGE = "integration.manage"

@dataclass
class User:
    """User data structure"""
    user_id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    permissions: Set[Permission]
    is_active: bool = True
    is_verified: bool = False
    created_at: datetime = None
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    two_factor_enabled: bool = False
    two_factor_secret: Optional[str] = None
    api_key_hash: Optional[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if isinstance(self.permissions, list):
            self.permissions = set(self.permissions)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['role'] = self.role.value
        data['permissions'] = [p.value for p in self.permissions]
        data['created_at'] = self.created_at.isoformat() if self.created_at else None
        data['last_login'] = self.last_login.isoformat() if self.last_login else None
        data['locked_until'] = self.locked_until.isoformat() if self.locked_until else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create from dictionary"""
        if 'role' in data:
            data['role'] = UserRole(data['role'])
        
        if 'permissions' in data and isinstance(data['permissions'], list):
            data['permissions'] = {Permission(p) for p in data['permissions']}
        
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'last_login' in data and isinstance(data['last_login'], str):
            data['last_login'] = datetime.fromisoformat(data['last_login'])
        if 'locked_until' in data and isinstance(data['locked_until'], str):
            data['locked_until'] = datetime.fromisoformat(data['locked_until'])
        
        return cls(**data)

class UserManagementError(Exception):
    """Custom exception for user management errors"""
    pass

class UserManager:
    """User management system with RBAC and security features"""
    
    def __init__(self, db_path: str = "/home/cbwinslow/reports/users.db"):
        self.db_path = db_path
        self._init_database()
        self.logger = logging.getLogger(__name__)
    
    def _init_database(self):
        """Initialize user database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL,
                        permissions TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT TRUE,
                        is_verified BOOLEAN DEFAULT FALSE,
                        created_at TEXT NOT NULL,
                        last_login TEXT,
                        failed_login_attempts INTEGER DEFAULT 0,
                        locked_until TEXT,
                        two_factor_enabled BOOLEAN DEFAULT FALSE,
                        two_factor_secret TEXT,
                        api_key_hash TEXT
                    )
                ''')
                
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)')
                
                conn.commit()
                self.logger.info("User database initialized")
                
        except Exception as e:
            self.logger.error(f"Error initializing user database: {e}")
            raise UserManagementError(f"Database initialization failed: {str(e)}")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using Argon2"""
        return argon2.hash(password)
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return argon2.verify(password, password_hash)
        except Exception:
            return False
    
    def create_user(self, username: str, password: str, email: str = "",
                   role: UserRole = UserRole.REPORT_VIEWER, 
                   permissions: Optional[Set[Permission]] = None) -> Optional[User]:
        """Create a new user"""
        try:
            password_hash = self._hash_password(password)
            permissions_json = json.dumps([p.value for p in permissions]) if permissions else "[]"
            
            user = User(
                user_id=f"user_{secrets.token_urlsafe(16)}",
                username=username,
                email=email,
                password_hash=password_hash,
                role=role,
                permissions=permissions or set(),
                is_active=True,
                is_verified=False,
                created_at=datetime.utcnow()
            )
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO users (
                        user_id, username, email, password_hash, role, permissions,
                        is_active, is_verified, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user.user_id, user.username, user.email, user.password_hash,
                    user.role.value, permissions_json, user.is_active, user.is_verified,
                    user.created_at.isoformat()
                ))
                
                conn.commit()
                self.logger.info(f"User created: {username}")
                return user
                
        except sqlite3.IntegrityError:
            self.logger.error(f"User already exists: {username}")
            return None
        except Exception as e:
            self.logger.error(f"Error creating user {username}: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, str]]:
        """Authenticate user and return session information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM users 
                    WHERE (username = ? OR email = ?) AND is_active = TRUE
                ''', (username, username))
                
                user_row = cursor.fetchone()
                
                if not user_row:
                    self.logger.warning(f"Authentication failed: user not found - {username}")
                    return None
                
                user_data = dict(user_row)
                user = User.from_dict(user_data)
                
                # Check if account is locked
                if user.locked_until and datetime.utcnow() < user.locked_until:
                    self.logger.warning(f"Authentication failed: account locked - {username}")
                    return None
                
                # Verify password
                if not self._verify_password(password, user.password_hash):
                    # Increment failed attempts
                    user.failed_login_attempts += 1
                    
                    # Lock account after 5 failed attempts
                    if user.failed_login_attempts >= 5:
                        user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    
                    # Update failed attempts
                    cursor.execute('''
                        UPDATE users 
                        SET failed_login_attempts = ?, locked_until = ?
                        WHERE user_id = ?
                    ''', (
                        user.failed_login_attempts,
                        user.locked_until.isoformat() if user.locked_until else None,
                        user.user_id
                    ))
                    
                    conn.commit()
                    self.logger.warning(f"Authentication failed: invalid password - {username}")
                    return None
                
                # Reset failed attempts
                user.failed_login_attempts = 0
                user.locked_until = None
                user.last_login = datetime.utcnow()
                
                # Update user
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = 0, locked_until = NULL, last_login = ?
                    WHERE user_id = ?
                ''', (user.last_login.isoformat(), user.user_id))
                
                conn.commit()
                
                # Generate JWT token
                jwt_payload = {
                    'user_id': user.user_id,
                    'username': user.username,
                    'role': user.role.value,
                    'permissions': [p.value for p in user.permissions],
                    'exp': datetime.utcnow() + timedelta(hours=24)
                }
                
                jwt_token = jwt.encode(jwt_payload, 'secret_key', algorithm='HS256')
                
                self.logger.info(f"User authenticated: {username}")
                
                return {
                    'user': user.to_dict(),
                    'jwt_token': jwt_token
                }
                
        except Exception as e:
            self.logger.error(f"Error authenticating user {username}: {e}")
            return None
    
    def validate_jwt_token(self, jwt_token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and return user information"""
        try:
            payload = jwt.decode(jwt_token, 'secret_key', algorithms=['HS256'])
            
            # Verify user still exists and is active
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM users 
                    WHERE user_id = ? AND is_active = TRUE
                ''', (payload['user_id'],))
                
                user_row = cursor.fetchone()
                
                if not user_row:
                    return None
                
                user_data = dict(user_row)
                user = User.from_dict(user_data)
                
                return {
                    'user_id': user.user_id,
                    'username': user.username,
                    'role': user.role.value,
                    'permissions': [p.value for p in user.permissions]
                }
                
        except jwt.ExpiredSignatureError:
            self.logger.debug("JWT token expired")
            return None
        except jwt.InvalidTokenError:
            self.logger.debug("Invalid JWT token")
            return None
        except Exception as e:
            self.logger.error(f"Error validating JWT token: {e}")
            return None
    
    def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """Get user permissions"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT role, permissions FROM users 
                    WHERE user_id = ? AND is_active = TRUE
                ''', (user_id,))
                
                row = cursor.fetchone()
                if not row:
                    return set()
                
                # Get role-based permissions
                role_permissions = self.get_role_permissions(UserRole(row['role']))
                
                # Add user-specific permissions
                user_permissions = []
                try:
                    user_perms = json.loads(row['permissions'])
                    user_permissions = [Permission(p) for p in user_perms]
                except (json.JSONDecodeError, ValueError):
                    pass
                
                # Combine and remove duplicates
                all_permissions = list(set(role_permissions + user_permissions))
                return set(all_permissions)
                
        except Exception as e:
            self.logger.error(f"Error getting permissions for user {user_id}: {e}")
            return set()
    
    def get_role_permissions(self, role: UserRole) -> List[Permission]:
        """Get permissions for a role"""
        role_permissions = {
            UserRole.ADMIN: list(Permission),
            UserRole.SYSTEM_ADMIN: [
                Permission.SYSTEM_ADMIN, Permission.SYSTEM_READ, Permission.SYSTEM_WRITE,
                Permission.USER_CREATE, Permission.USER_READ, Permission.USER_UPDATE, 
                Permission.USER_DELETE, Permission.USER_MANAGE_ROLES,
                Permission.CONFIG_READ, Permission.CONFIG_UPDATE, Permission.CONFIG_MANAGE,
                Permission.SECURITY_AUDIT, Permission.SECURITY_MONITOR, Permission.SECURITY_ALERT
            ],
            UserRole.REPORT_VIEWER: [
                Permission.REPORT_READ, Permission.DASHBOARD_VIEW
            ],
            UserRole.AUDITOR: [
                Permission.SYSTEM_READ, Permission.REPORT_READ, Permission.SECURITY_AUDIT,
                Permission.VIEW_AUDIT_LOGS, Permission.DASHBOARD_VIEW
            ],
            UserRole.DEVELOPER: [
                Permission.SYSTEM_ADMIN, Permission.SYSTEM_READ, Permission.SYSTEM_WRITE,
                Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_UPDATE,
                Permission.REPORT_DELETE, Permission.API_ACCESS, Permission.API_ADMIN
            ],
            UserRole.GUEST: [
                Permission.REPORT_READ, Permission.DASHBOARD_VIEW
            ]
        }
        
        return role_permissions.get(role, [])
    
    def has_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if user has specific permission"""
        user_permissions = self.get_user_permissions(user_id)
        return permission in user_permissions
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List all users"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT user_id, username, email, role, is_active, created_at, last_login
                    FROM users 
                    ORDER BY created_at DESC
                ''')
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            self.logger.error(f"Error listing users: {e}")
            return []

# Example usage and testing
if __name__ == "__main__":
    import tempfile
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = os.path.join(temp_dir, "test_users.db")
        
        print("👥 User Management System Demo")
        print("=" * 40)
        
        # Initialize user manager
        try:
            user_manager = UserManager(db_path=temp_path)
            print("✅ User manager initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize user manager: {e}")
            exit(1)
        
        # Test user creation
        print("\n1. Testing user creation...")
        try:
            new_user = user_manager.create_user(
                username="testuser",
                password="SecurePass123!",
                email="test@example.com",
                role=UserRole.REPORT_VIEWER
            )
            
            if new_user:
                print("✅ User created successfully")
                print(f"   Username: {new_user.username}")
                print(f"   Role: {new_user.role.value}")
                print(f"   User ID: {new_user.user_id}")
            else:
                print("❌ User creation failed")
                
        except Exception as e:
            print(f"❌ User creation failed: {e}")
        
        # Test user authentication
        print("\n2. Testing user authentication...")
        try:
            auth_result = user_manager.authenticate_user("testuser", "SecurePass123!")
            if auth_result:
                print("✅ User authenticated successfully")
                print(f"   JWT Token: {auth_result['jwt_token'][:20]}...")
                user_info = auth_result['user']
                print(f"   User ID: {user_info['user_id']}")
                print(f"   Username: {user_info['username']}")
                print(f"   Role: {user_info['role']}")
            else:
                print("❌ User authentication failed")
        except Exception as e:
            print(f"❌ User authentication failed: {e}")
        
        # Test JWT token validation
        print("\n3. Testing JWT token validation...")
        try:
            if auth_result:
                validated_user = user_manager.validate_jwt_token(auth_result['jwt_token'])
                if validated_user:
                    print("✅ JWT token validated successfully")
                    print(f"   Username: {validated_user['username']}")
                    print(f"   Role: {validated_user['role']}")
                else:
                    print("❌ JWT token validation failed")
            else:
                print("⚠️ Skipping JWT validation (no token available)")
        except Exception as e:
            print(f"❌ JWT token validation failed: {e}")
        
        # Test user permissions
        print("\n4. Testing user permissions...")
        try:
            if new_user:
                permissions = user_manager.get_user_permissions(new_user.user_id)
                print("✅ User permissions retrieved successfully")
                print(f"   Permissions: {[p.value for p in permissions]}")
                
                has_report_perm = user_manager.has_permission(new_user.user_id, Permission.REPORT_READ)
                print(f"   Has report read permission: {has_report_perm}")
                
                has_admin_perm = user_manager.has_permission(new_user.user_id, Permission.SYSTEM_ADMIN)
                print(f"   Has system admin permission: {has_admin_perm}")
            else:
                print("⚠️ Skipping permissions test (no user available)")
        except Exception as e:
            print(f"❌ User permissions test failed: {e}")
        
        # Test user listing
        print("\n5. Testing user listing...")
        try:
            users = user_manager.list_users()
            print("✅ User listing successful")
            print(f"   Users found: {len(users)}")
            
            for user in users[:3]:  # Show first 3 users
                print(f"   - {user['username']} ({user['role']}) - Active: {user['is_active']}")
        except Exception as e:
            print(f"❌ User listing failed: {e}")
        
        print("\n🎯 User Management System Demo Complete")
        print("This demonstrates the core functionality of the user management system.")
        print("In a production environment, this would integrate with:")
        print("  • LDAP/Active Directory for enterprise authentication")
        print("  • SAML/OAuth2 for single sign-on")
        print("  • Multi-factor authentication for enhanced security")
        print("  • Advanced role-based access control")
        print("  • Comprehensive audit logging and compliance")
        print("  • Secure session management")
        print("  • API key management for programmatic access")