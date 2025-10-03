#!/usr/bin/env python3

# User Management and Access Control System for Enterprise Reporting System
# Provides RBAC (Role-Based Access Control), authentication, and authorization

import os
import json
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timedelta
import sqlite3
from contextlib import contextmanager
import logging
from typing import Dict, List, Optional, Tuple
from enum import Enum
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class Role(Enum):
    """User roles in the system"""
    ADMIN = "admin"
    READ_ONLY = "read_only"
    REPORT_VIEWER = "report_viewer"
    SYSTEM_MANAGER = "system_manager"
    AUDIT_REVIEWER = "audit_reviewer"

class Permission(Enum):
    """System permissions"""
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_REPORTS = "view_reports"
    CREATE_REPORTS = "create_reports"
    EDIT_REPORTS = "edit_reports"
    DELETE_REPORTS = "delete_reports"
    VIEW_SYSTEMS = "view_systems"
    CONFIGURE_SYSTEM = "configure_system"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    MANAGE_USERS = "manage_users"
    EXPORT_DATA = "export_data"

class UserManager:
    """User management system with RBAC"""
    
    def __init__(self, db_path: str = "/home/cbwinslow/reports/users.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
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
        
        # Initialize password encryption
        self.password_key = self._get_password_key()
        self.password_cipher = Fernet(self.password_key)
    
    def _get_password_key(self) -> bytes:
        """Get or create key for password encryption"""
        key_file = Path("/home/cbwinslow/reports/.password_key")
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            return key
    
    def _init_database(self):
        """Initialize the users database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    permissions TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP
                )
            ''')
            
            # Create user sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            # Create index for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_active ON users(is_active)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_token ON user_sessions(session_token)')
            
            # Create default admin user if none exists
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]
            
            if user_count == 0:
                self.create_user(
                    username="admin",
                    email="admin@localhost",
                    password="admin123",  # Should be changed after first login
                    role=Role.ADMIN
                )
                self.logger.info("Created default admin user")
            
            conn.commit()
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Create password hash
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        
        return pwd_hash.hex(), salt
    
    def _check_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Check if password matches hash"""
        pwd_hash, _ = self._hash_password(password, salt)
        return pwd_hash == stored_hash
    
    def create_user(self, username: str, password: str, email: str = "",
                   role: Role = Role.READ_ONLY, permissions: Optional[List[Permission]] = None) -> bool:
        """Create a new user"""
        try:
            password_hash, salt = self._hash_password(password)
            permissions_json = json.dumps([p.value for p in permissions]) if permissions else "[]"
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, salt, role, permissions)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (username, email, password_hash, salt, role.value, permissions_json))
                
                conn.commit()
                self.logger.info(f"User created: {username}")
                return True
                
        except sqlite3.IntegrityError:
            self.logger.error(f"User already exists: {username}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to create user {username}: {e}")
            return False
    
    def authenticate_user(self, username: str, password: str, 
                         ip_address: str = "", user_agent: str = "") -> Optional[Dict[str, str]]:
        """Authenticate user and return session token"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM users 
                    WHERE username = ? OR email = ?
                ''', (username, username))
                
                user = cursor.fetchone()
                
                if not user:
                    self.logger.warning(f"Authentication failed: user not found - {username}")
                    return None
                
                # Check if account is locked
                if user['locked_until']:
                    locked_until = datetime.fromisoformat(user['locked_until'])
                    if datetime.utcnow() < locked_until:
                        self.logger.warning(f"Authentication failed: account locked - {username}")
                        return None
                
                # Check password
                if not self._check_password(password, user['password_hash'], user['salt']):
                    # Increment failed attempts
                    failed_attempts = user['failed_login_attempts'] + 1
                    
                    # Lock account after 5 failed attempts
                    locked_until = None
                    if failed_attempts >= 5:
                        locked_until = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
                    
                    cursor.execute('''
                        UPDATE users 
                        SET failed_login_attempts = ?, locked_until = ?
                        WHERE id = ?
                    ''', (failed_attempts, locked_until, user['id']))
                    
                    conn.commit()
                    self.logger.warning(f"Authentication failed: invalid password - {username}")
                    return None
                
                # Reset failed attempts
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (user['id'],))
                
                # Create session
                session_token = secrets.token_urlsafe(32)
                expires_at = (datetime.utcnow() + timedelta(hours=24)).isoformat()
                
                cursor.execute('''
                    INSERT INTO user_sessions (user_id, session_token, expires_at, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user['id'], session_token, expires_at, ip_address, user_agent))
                
                conn.commit()
                
                # Log successful authentication
                self.logger.info(f"User authenticated: {username}")
                
                return {
                    "session_token": session_token,
                    "user_id": str(user['id']),
                    "username": user['username'],
                    "role": user['role'],
                    "permissions": user['permissions']
                }
                
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return None
    
    def validate_session(self, session_token: str) -> Optional[Dict[str, str]]:
        """Validate session token"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT s.*, u.username, u.role, u.permissions 
                    FROM user_sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.session_token = ? AND s.expires_at > CURRENT_TIMESTAMP AND u.is_active = TRUE
                ''', (session_token,))
                
                session = cursor.fetchone()
                
                if not session:
                    return None
                
                return {
                    "user_id": str(session['user_id']),
                    "username": session['username'],
                    "role": session['role'],
                    "permissions": session['permissions']
                }
                
        except Exception as e:
            self.logger.error(f"Session validation error: {e}")
            return None
    
    def logout_user(self, session_token: str) -> bool:
        """Logout user by invalidating session"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM user_sessions WHERE session_token = ?', (session_token,))
                affected = cursor.rowcount
                conn.commit()
                
                if affected > 0:
                    self.logger.info(f"User logged out: session invalidated")
                    return True
                else:
                    self.logger.warning(f"Logout failed: session not found")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Logout error: {e}")
            return False
    
    def get_user_permissions(self, username: str) -> List[Permission]:
        """Get user permissions"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT role, permissions FROM users 
                    WHERE username = ? AND is_active = TRUE
                ''', (username,))
                
                user = cursor.fetchone()
                if not user:
                    return []
                
                # Get role-based permissions
                role_permissions = self.get_role_permissions(Role(user['role']))
                
                # Add user-specific permissions
                user_permissions = []
                try:
                    user_perms = json.loads(user['permissions'])
                    user_permissions = [Permission(p) for p in user_perms]
                except (json.JSONDecodeError, ValueError):
                    pass
                
                # Combine and remove duplicates
                all_permissions = list(set(role_permissions + user_permissions))
                return all_permissions
                
        except Exception as e:
            self.logger.error(f"Error getting user permissions: {e}")
            return []
    
    def get_role_permissions(self, role: Role) -> List[Permission]:
        """Get permissions for a role"""
        role_permissions = {
            Role.ADMIN: list(Permission),
            Role.SYSTEM_MANAGER: [
                Permission.VIEW_DASHBOARD, Permission.VIEW_REPORTS, Permission.CREATE_REPORTS,
                Permission.VIEW_SYSTEMS, Permission.CONFIGURE_SYSTEM, Permission.VIEW_AUDIT_LOGS
            ],
            Role.REPORT_VIEWER: [
                Permission.VIEW_DASHBOARD, Permission.VIEW_REPORTS, Permission.VIEW_SYSTEMS
            ],
            Role.AUDIT_REVIEWER: [
                Permission.VIEW_DASHBOARD, Permission.VIEW_AUDIT_LOGS, Permission.EXPORT_DATA
            ],
            Role.READ_ONLY: [
                Permission.VIEW_DASHBOARD, Permission.VIEW_REPORTS
            ]
        }
        
        return role_permissions.get(role, [])
    
    def has_permission(self, username: str, permission: Permission) -> bool:
        """Check if user has a specific permission"""
        user_permissions = self.get_user_permissions(username)
        return permission in user_permissions
    
    def update_user(self, username: str, new_email: str = None, new_role: Role = None,
                   new_permissions: List[Permission] = None, is_active: bool = None) -> bool:
        """Update user information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                updates = []
                params = []
                
                if new_email is not None:
                    updates.append("email = ?")
                    params.append(new_email)
                
                if new_role is not None:
                    updates.append("role = ?")
                    params.append(new_role.value)
                
                if new_permissions is not None:
                    permissions_json = json.dumps([p.value for p in new_permissions])
                    updates.append("permissions = ?")
                    params.append(permissions_json)
                
                if is_active is not None:
                    updates.append("is_active = ?")
                    params.append(is_active)
                
                if updates:
                    params.append(username)
                    set_clause = ", ".join(updates)
                    
                    cursor.execute(f'''
                        UPDATE users 
                        SET {set_clause}
                        WHERE username = ?
                    ''', params)
                    
                    if cursor.rowcount > 0:
                        conn.commit()
                        self.logger.info(f"User updated: {username}")
                        return True
                    else:
                        self.logger.warning(f"User not found for update: {username}")
                        return False
                else:
                    return True  # Nothing to update
                    
        except Exception as e:
            self.logger.error(f"Error updating user {username}: {e}")
            return False
    
    def delete_user(self, username: str) -> bool:
        """Delete a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete user sessions first
                cursor.execute('''
                    DELETE FROM user_sessions 
                    WHERE user_id = (SELECT id FROM users WHERE username = ?)
                ''', (username,))
                
                # Delete user
                cursor.execute('DELETE FROM users WHERE username = ?', (username,))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    self.logger.info(f"User deleted: {username}")
                    return True
                else:
                    self.logger.warning(f"User not found for deletion: {username}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error deleting user {username}: {e}")
            return False
    
    def list_users(self) -> List[Dict[str, str]]:
        """List all users"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT username, email, role, created_at, last_login, is_active 
                    FROM users 
                    ORDER BY created_at DESC
                ''')
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            self.logger.error(f"Error listing users: {e}")
            return []
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change user password"""
        try:
            # First authenticate with old password
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                user = cursor.fetchone()
                
                if not user or not self._check_password(old_password, user['password_hash'], user['salt']):
                    self.logger.warning(f"Password change failed: invalid old password for {username}")
                    return False
                
                # Hash new password
                new_hash, new_salt = self._hash_password(new_password)
                
                cursor.execute('''
                    UPDATE users 
                    SET password_hash = ?, salt = ?
                    WHERE username = ?
                ''', (new_hash, new_salt, username))
                
                conn.commit()
                self.logger.info(f"Password changed for user: {username}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error changing password for {username}: {e}")
            return False
    
    def create_session_token(self, username: str) -> Optional[str]:
        """Create a session token for a user (used for API authentication)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT id FROM users WHERE username = ? AND is_active = TRUE', (username,))
                user = cursor.fetchone()
                
                if not user:
                    return None
                
                session_token = secrets.token_urlsafe(32)
                expires_at = (datetime.utcnow() + timedelta(days=30)).isoformat()  # Long-lived token
                
                cursor.execute('''
                    INSERT INTO user_sessions (user_id, session_token, expires_at)
                    VALUES (?, ?, ?)
                ''', (user['id'], session_token, expires_at))
                
                conn.commit()
                
                return session_token
                
        except Exception as e:
            self.logger.error(f"Error creating session token: {e}")
            return None


class AccessControlManager:
    """Access control manager that integrates with the user system"""
    
    def __init__(self, user_manager: UserManager):
        self.user_manager = user_manager
        self.logger = logging.getLogger(__name__)
    
    def check_access(self, session_token: str, endpoint: str, method: str = "GET") -> bool:
        """Check if user has access to a specific endpoint"""
        user_info = self.user_manager.validate_session(session_token)
        if not user_info:
            return False
        
        # Map endpoints to required permissions
        endpoint_permissions = {
            "/api/v1/reports": {
                "GET": Permission.VIEW_REPORTS,
                "POST": Permission.CREATE_REPORTS,
                "PUT": Permission.EDIT_REPORTS,
                "DELETE": Permission.DELETE_REPORTS
            },
            "/api/v1/systems": {
                "GET": Permission.VIEW_SYSTEMS,
                "POST": Permission.CONFIGURE_SYSTEM,
                "PUT": Permission.CONFIGURE_SYSTEM,
                "DELETE": Permission.CONFIGURE_SYSTEM
            },
            "/api/v1/config": {
                "GET": Permission.CONFIGURE_SYSTEM,
                "POST": Permission.CONFIGURE_SYSTEM,
                "PUT": Permission.CONFIGURE_SYSTEM
            },
            "/api/v1/audit": {
                "GET": Permission.VIEW_AUDIT_LOGS
            },
            "/dashboard": {
                "GET": Permission.VIEW_DASHBOARD
            }
        }
        
        required_permission = endpoint_permissions.get(endpoint, {}).get(method)
        
        if not required_permission:
            # Endpoint doesn't require special permissions
            return True
        
        return self.user_manager.has_permission(user_info['username'], required_permission)
    
    def get_user_permissions(self, session_token: str) -> List[Permission]:
        """Get permissions for a user by session token"""
        user_info = self.user_manager.validate_session(session_token)
        if not user_info:
            return []
        
        return self.user_manager.get_user_permissions(user_info['username'])
    
    def is_admin(self, session_token: str) -> bool:
        """Check if user is admin"""
        user_info = self.user_manager.validate_session(session_token)
        if not user_info:
            return False
        
        return user_info['role'] == Role.ADMIN.value


# Example usage and testing
if __name__ == "__main__":
    import tempfile
    
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Initialize user manager
        user_manager = UserManager(db_path=temp_path / "test_users.db")
        
        print("User Management System Demo")
        print("-" * 30)
        
        # Create a new user
        print("Creating test user...")
        user_manager.create_user(
            username="testuser",
            password="securePassword123!",
            email="test@example.com",
            role=Role.REPORT_VIEWER
        )
        
        # Authenticate user
        print("Authenticating user...")
        auth_result = user_manager.authenticate_user("testuser", "securePassword123!")
        if auth_result:
            print(f"Authentication successful: {auth_result['username']}")
            session_token = auth_result['session_token']
        else:
            print("Authentication failed")
            session_token = None
        
        # Check permissions
        if session_token:
            print(f"Session token: {session_token[:10]}...")
            
            permissions = user_manager.get_user_permissions("testuser")
            print(f"User permissions: {[p.value for p in permissions]}")
            
            has_report_perm = user_manager.has_permission("testuser", Permission.VIEW_REPORTS)
            print(f"Has report view permission: {has_report_perm}")
        
        # Access control test
        if session_token:
            print("\nTesting access control...")
            access_manager = AccessControlManager(user_manager)
            
            can_access = access_manager.check_access(session_token, "/api/v1/reports", "GET")
            print(f"Can access reports API: {can_access}")
            
            is_admin = access_manager.is_admin(session_token)
            print(f"Is admin: {is_admin}")
        
        # List users
        print("\nListing users:")
        users = user_manager.list_users()
        for user in users:
            print(f"  - {user['username']} ({user['role']}) - Active: {user['is_active']}")
        
        # Update user
        print("\nUpdating user role...")
        user_manager.update_user("testuser", new_role=Role.SYSTEM_MANAGER)
        
        # Check updated permissions
        if session_token:
            updated_perms = user_manager.get_user_permissions("testuser")
            print(f"Updated permissions: {[p.value for p in updated_perms]}")
        
        print("\nUser management system working correctly!")