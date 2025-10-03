"""
User Management and Access Control System for Enterprise Reporting System
"""

import os
import json
import hashlib
import secrets
import logging
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import sqlite3
from contextlib import contextmanager
import jwt
from cryptography.fernet import Fernet
from passlib.hash import argon2, bcrypt
import asyncio
from functools import wraps

logger = logging.getLogger(__name__)

class UserRole(Enum):
    """User roles in the system"""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
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
    session_tokens: List[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.session_tokens is None:
            self.session_tokens = []
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
        # Convert role string to enum
        if 'role' in data:
            data['role'] = UserRole(data['role'])
        
        # Convert permissions list to set
        if 'permissions' in data and isinstance(data['permissions'], list):
            data['permissions'] = {Permission(p) for p in data['permissions']}
        
        # Convert datetime strings to datetime objects
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'last_login' in data and isinstance(data['last_login'], str):
            data['last_login'] = datetime.fromisoformat(data['last_login'])
        if 'locked_until' in data and isinstance(data['locked_until'], str):
            data['locked_until'] = datetime.fromisoformat(data['locked_until'])
        
        return cls(**data)

@dataclass
class UserSession:
    """User session data structure"""
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    last_activity: datetime = None
    
    def __post_init__(self):
        if self.last_activity is None:
            self.last_activity = self.created_at
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_active(self) -> bool:
        """Check if session is active"""
        return not self.is_expired()
    
    def extend_session(self, minutes: int = 30):
        """Extend session expiration"""
        self.expires_at = datetime.utcnow() + timedelta(minutes=minutes)
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'last_activity': self.last_activity.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserSession':
        """Create from dictionary"""
        # Convert datetime strings to datetime objects
        if 'created_at' in data and isinstance(data['created_at'], str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if 'expires_at' in data and isinstance(data['expires_at'], str):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        if 'last_activity' in data and isinstance(data['last_activity'], str):
            data['last_activity'] = datetime.fromisoformat(data['last_activity'])
        
        return cls(**data)

@dataclass
class UserConfig:
    """User management configuration"""
    # Database settings
    db_path: str = "/home/cbwinslow/reports/users.db"
    
    # Security settings
    password_hash_algorithm: str = "argon2"  # argon2, bcrypt
    password_min_length: int = 12
    password_require_complexity: bool = True
    session_timeout_minutes: int = 60
    max_failed_login_attempts: int = 5
    account_lockout_duration_minutes: int = 30
    enable_two_factor_auth: bool = True
    two_factor_token_validity_minutes: int = 10
    
    # API settings
    jwt_secret: Optional[str] = None
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    enable_api_keys: bool = True
    api_key_length: int = 32
    
    # Password policy
    password_history_size: int = 10
    password_min_age_days: int = 1
    password_max_age_days: int = 90
    enable_password_expiration: bool = True
    
    # Session management
    max_sessions_per_user: int = 5
    enable_session_cleanup: bool = True
    session_cleanup_interval_minutes: int = 60
    
    # Audit logging
    enable_audit_logging: bool = True
    audit_log_retention_days: int = 90
    
    # Rate limiting
    enable_rate_limiting: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_window_seconds: int = 60
    
    def __post_init__(self):
        if self.jwt_secret is None:
            # Generate JWT secret if not provided
            self.jwt_secret = secrets.token_urlsafe(32)

class UserManagerError(Exception):
    """Custom exception for user management errors"""
    pass

class UserManager:
    """User management system with RBAC and security features"""
    
    def __init__(self, config: UserConfig):
        self.config = config
        self.db_path = Path(config.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Initialize encryption
        self._init_encryption()
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize background tasks
        self.background_tasks = set()
        self._start_background_tasks()
        
        self.logger.info("User management system initialized")
    
    def _init_database(self):
        """Initialize user database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create users table
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
                        api_key_hash TEXT,
                        password_history TEXT,
                        last_password_change TEXT,
                        session_tokens TEXT
                    )
                ''')
                
                # Create sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        last_activity TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users (user_id)
                    )
                ''')
                
                # Create audit log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        user_id TEXT,
                        action TEXT NOT NULL,
                        resource_type TEXT,
                        resource_id TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        success BOOLEAN,
                        details TEXT
                    )
                ''')
                
                # Create indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)')
                
                conn.commit()
                
                # Create default admin user if none exists
                cursor.execute('SELECT COUNT(*) FROM users')
                user_count = cursor.fetchone()[0]
                
                if user_count == 0:
                    self._create_default_admin()
                
                self.logger.info("User database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Error initializing user database: {e}")
            raise UserManagerError(f"Database initialization failed: {str(e)}")
    
    def _init_encryption(self):
        """Initialize encryption for sensitive data"""
        try:
            # Get or create encryption key
            key_file = Path("/home/cbwinslow/reports/.user_encryption_key")
            
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(self.encryption_key)
                os.chmod(key_file, 0o600)  # Restrict permissions
            
            self.cipher = Fernet(self.encryption_key)
            
            self.logger.info("User data encryption initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing encryption: {e}")
            raise UserManagerError(f"Encryption initialization failed: {str(e)}")
    
    def _create_default_admin(self):
        """Create default admin user"""
        try:
            admin_password = "Admin123!"  # Should be changed after first login
            password_hash = self._hash_password(admin_password)
            
            default_admin = User(
                user_id=f"user_{secrets.token_urlsafe(16)}",
                username="admin",
                email="admin@localhost",
                password_hash=password_hash,
                role=UserRole.ADMIN,
                permissions=set(Permission),  # All permissions for admin
                is_active=True,
                is_verified=True,
                created_at=datetime.utcnow()
            )
            
            self._save_user(default_admin)
            
            self.logger.info("Default admin user created")
            
        except Exception as e:
            self.logger.error(f"Error creating default admin user: {e}")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using configured algorithm"""
        try:
            if self.config.password_hash_algorithm == "argon2":
                return argon2.hash(password)
            elif self.config.password_hash_algorithm == "bcrypt":
                return bcrypt.hash(password)
            else:
                # Fallback to argon2
                return argon2.hash(password)
                
        except Exception as e:
            self.logger.error(f"Error hashing password: {e}")
            raise UserManagerError(f"Password hashing failed: {str(e)}")
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            if self.config.password_hash_algorithm == "argon2":
                return argon2.verify(password, password_hash)
            elif self.config.password_hash_algorithm == "bcrypt":
                return bcrypt.verify(password, password_hash)
            else:
                # Fallback to argon2
                return argon2.verify(password, password_hash)
                
        except Exception as e:
            self.logger.error(f"Error verifying password: {e}")
            return False
    
    def _validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Validate password strength"""
        if len(password) < self.config.password_min_length:
            return False, f"Password must be at least {self.config.password_min_length} characters long"
        
        if self.config.password_require_complexity:
            if not any(c.isupper() for c in password):
                return False, "Password must contain at least one uppercase letter"
            
            if not any(c.islower() for c in password):
                return False, "Password must contain at least one lowercase letter"
            
            if not any(c.isdigit() for c in password):
                return False, "Password must contain at least one digit"
            
            if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    def _generate_api_key(self) -> str:
        """Generate secure API key"""
        return secrets.token_urlsafe(self.config.api_key_length)
    
    def _hash_api_key(self, api_key: str) -> str:
        """Hash API key for storage"""
        return hashlib.sha256(api_key.encode('utf-8')).hexdigest()
    
    @contextmanager
    def _get_db_connection(self):
        """Get database connection with proper error handling"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                conn.close()
    
    def _save_user(self, user: User) -> bool:
        """Save user to database"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                # Convert permissions to JSON string
                permissions_json = json.dumps([p.value for p in user.permissions])
                
                # Convert session tokens to JSON string
                session_tokens_json = json.dumps(user.session_tokens)
                
                cursor.execute('''
                    INSERT OR REPLACE INTO users (
                        user_id, username, email, password_hash, role, permissions,
                        is_active, is_verified, created_at, last_login,
                        failed_login_attempts, locked_until, two_factor_enabled,
                        two_factor_secret, api_key_hash, session_tokens
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user.user_id, user.username, user.email, user.password_hash,
                    user.role.value, permissions_json, user.is_active, user.is_verified,
                    user.created_at.isoformat(), 
                    user.last_login.isoformat() if user.last_login else None,
                    user.failed_login_attempts,
                    user.locked_until.isoformat() if user.locked_until else None,
                    user.two_factor_enabled, user.two_factor_secret, user.api_key_hash,
                    session_tokens_json
                ))
                
                conn.commit()
                self.logger.info(f"User saved: {user.username}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error saving user {user.username}: {e}")
            return False
    
    def _load_user(self, user_id: str = None, username: str = None, email: str = None) -> Optional[User]:
        """Load user from database"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                if user_id:
                    cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
                elif username:
                    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
                elif email:
                    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
                else:
                    return None
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Convert row to user object
                user_data = dict(row)
                
                # Parse permissions from JSON
                if user_data['permissions']:
                    try:
                        permissions_list = json.loads(user_data['permissions'])
                        user_data['permissions'] = {Permission(p) for p in permissions_list}
                    except (json.JSONDecodeError, ValueError):
                        user_data['permissions'] = set()
                
                # Parse session tokens from JSON
                if user_data['session_tokens']:
                    try:
                        user_data['session_tokens'] = json.loads(user_data['session_tokens'])
                    except (json.JSONDecodeError, ValueError):
                        user_data['session_tokens'] = []
                
                # Convert datetime strings to datetime objects
                datetime_fields = ['created_at', 'last_login', 'locked_until']
                for field in datetime_fields:
                    if user_data[field]:
                        try:
                            user_data[field] = datetime.fromisoformat(user_data[field])
                        except ValueError:
                            user_data[field] = None
                
                return User(**user_data)
                
        except Exception as e:
            self.logger.error(f"Error loading user: {e}")
            return None
    
    def _save_session(self, session: UserSession) -> bool:
        """Save session to database"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO user_sessions (
                        session_id, user_id, created_at, expires_at,
                        ip_address, user_agent, last_activity
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session.session_id, session.user_id,
                    session.created_at.isoformat(),
                    session.expires_at.isoformat(),
                    session.ip_address, session.user_agent,
                    session.last_activity.isoformat()
                ))
                
                conn.commit()
                self.logger.debug(f"Session saved: {session.session_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error saving session {session.session_id}: {e}")
            return False
    
    def _load_session(self, session_id: str) -> Optional[UserSession]:
        """Load session from database"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM user_sessions WHERE session_id = ?', (session_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Convert row to session object
                session_data = dict(row)
                
                # Convert datetime strings to datetime objects
                datetime_fields = ['created_at', 'expires_at', 'last_activity']
                for field in datetime_fields:
                    if session_data[field]:
                        try:
                            session_data[field] = datetime.fromisoformat(session_data[field])
                        except ValueError:
                            session_data[field] = None
                
                return UserSession(**session_data)
                
        except Exception as e:
            self.logger.error(f"Error loading session {session_id}: {e}")
            return None
    
    def _delete_session(self, session_id: str) -> bool:
        """Delete session from database"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('DELETE FROM user_sessions WHERE session_id = ?', (session_id,))
                conn.commit()
                
                if cursor.rowcount > 0:
                    self.logger.debug(f"Session deleted: {session_id}")
                    return True
                else:
                    self.logger.debug(f"Session not found for deletion: {session_id}")
                    return False
                
        except Exception as e:
            self.logger.error(f"Error deleting session {session_id}: {e}")
            return False
    
    def _log_audit_event(self, user_id: Optional[str], action: str, 
                        resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                        ip_address: Optional[str] = None, user_agent: Optional[str] = None,
                        success: bool = True, details: Optional[Dict[str, Any]] = None):
        """Log audit event"""
        if not self.config.enable_audit_logging:
            return
        
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO audit_log (
                        timestamp, user_id, action, resource_type, resource_id,
                        ip_address, user_agent, success, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.utcnow().isoformat(),
                    user_id, action, resource_type, resource_id,
                    ip_address, user_agent, success,
                    json.dumps(details) if details else None
                ))
                
                conn.commit()
                self.logger.debug(f"Audit event logged: {action}")
                
        except Exception as e:
            self.logger.error(f"Error logging audit event: {e}")
    
    def create_user(self, username: str, email: str, password: str, 
                   role: UserRole = UserRole.VIEWER, 
                   permissions: Optional[Set[Permission]] = None) -> Optional[User]:
        """Create a new user"""
        try:
            # Validate input
            if not username or not email or not password:
                raise UserManagerError("Username, email, and password are required")
            
            # Validate password strength
            is_strong, message = self._validate_password_strength(password)
            if not is_strong:
                raise UserManagerError(f"Weak password: {message}")
            
            # Check if user already exists
            existing_user = self._load_user(username=username) or self._load_user(email=email)
            if existing_user:
                raise UserManagerError("User with this username or email already exists")
            
            # Hash password
            password_hash = self._hash_password(password)
            
            # Create user object
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
            
            # Save user
            if self._save_user(user):
                self._log_audit_event(
                    user_id=user.user_id,
                    action="user_create",
                    resource_type="user",
                    resource_id=user.user_id,
                    success=True,
                    details={"username": username, "role": role.value}
                )
                return user
            else:
                self._log_audit_event(
                    user_id=None,
                    action="user_create",
                    resource_type="user",
                    resource_id=None,
                    success=False,
                    details={"username": username, "error": "Failed to save user"}
                )
                return None
                
        except Exception as e:
            self.logger.error(f"Error creating user {username}: {e}")
            raise UserManagerError(f"User creation failed: {str(e)}")
    
    def authenticate_user(self, username: str, password: str, 
                         ip_address: Optional[str] = None, 
                         user_agent: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Authenticate user and return session information"""
        try:
            # Load user
            user = self._load_user(username=username) or self._load_user(email=username)
            if not user:
                self._log_audit_event(
                    user_id=None,
                    action="user_login",
                    resource_type="authentication",
                    resource_id=None,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details={"username": username, "error": "User not found"}
                )
                return None
            
            # Check if user is active
            if not user.is_active:
                self._log_audit_event(
                    user_id=user.user_id,
                    action="user_login",
                    resource_type="authentication",
                    resource_id=user.user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details={"username": username, "error": "User account is inactive"}
                )
                return None
            
            # Check if account is locked
            if user.locked_until and datetime.utcnow() < user.locked_until:
                self._log_audit_event(
                    user_id=user.user_id,
                    action="user_login",
                    resource_type="authentication",
                    resource_id=user.user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details={"username": username, "error": "Account is locked"}
                )
                return None
            
            # Verify password
            if not self._verify_password(password, user.password_hash):
                # Increment failed login attempts
                user.failed_login_attempts += 1
                
                # Lock account if too many failed attempts
                if user.failed_login_attempts >= self.config.max_failed_login_attempts:
                    user.locked_until = datetime.utcnow() + timedelta(
                        minutes=self.config.account_lockout_duration_minutes
                    )
                    self._log_audit_event(
                        user_id=user.user_id,
                        action="user_login",
                        resource_type="authentication",
                        resource_id=user.user_id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        success=False,
                        details={"username": username, "error": "Account locked due to too many failed attempts"}
                    )
                else:
                    self._log_audit_event(
                        user_id=user.user_id,
                        action="user_login",
                        resource_type="authentication",
                        resource_id=user.user_id,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        success=False,
                        details={"username": username, "error": "Invalid password"}
                    )
                
                # Save updated user
                self._save_user(user)
                return None
            
            # Reset failed login attempts
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            
            # Save updated user
            self._save_user(user)
            
            # Create session
            session = UserSession(
                session_id=f"sess_{secrets.token_urlsafe(32)}",
                user_id=user.user_id,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(
                    minutes=self.config.session_timeout_minutes
                ),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            # Save session
            if not self._save_session(session):
                self._log_audit_event(
                    user_id=user.user_id,
                    action="user_login",
                    resource_type="authentication",
                    resource_id=user.user_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details={"username": username, "error": "Failed to create session"}
                )
                return None
            
            # Generate JWT token
            jwt_payload = {
                'user_id': user.user_id,
                'username': user.username,
                'role': user.role.value,
                'permissions': [p.value for p in user.permissions],
                'session_id': session.session_id,
                'exp': datetime.utcnow() + timedelta(hours=self.config.jwt_expiration_hours),
                'iat': datetime.utcnow()
            }
            
            jwt_token = jwt.encode(
                jwt_payload, 
                self.config.jwt_secret, 
                algorithm=self.config.jwt_algorithm
            )
            
            # Log successful authentication
            self._log_audit_event(
                user_id=user.user_id,
                action="user_login",
                resource_type="authentication",
                resource_id=user.user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True,
                details={"username": username}
            )
            
            return {
                'user': user.to_dict(),
                'session': session.to_dict(),
                'jwt_token': jwt_token,
                'expires_at': session.expires_at.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error authenticating user {username}: {e}")
            raise UserManagerError(f"Authentication failed: {str(e)}")
    
    def validate_session(self, session_id: str) -> Optional[User]:
        """Validate session and return user"""
        try:
            # Load session
            session = self._load_session(session_id)
            if not session:
                return None
            
            # Check if session is expired
            if session.is_expired():
                # Delete expired session
                self._delete_session(session_id)
                return None
            
            # Update session activity
            session.update_activity()
            self._save_session(session)
            
            # Load user
            user = self._load_user(user_id=session.user_id)
            if not user or not user.is_active:
                return None
            
            return user
            
        except Exception as e:
            self.logger.error(f"Error validating session {session_id}: {e}")
            return None
    
    def validate_jwt_token(self, jwt_token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token and return payload"""
        try:
            payload = jwt.decode(
                jwt_token,
                self.config.jwt_secret,
                algorithms=[self.config.jwt_algorithm]
            )
            
            # Verify session is still valid
            session = self._load_session(payload.get('session_id'))
            if not session or session.is_expired():
                return None
            
            # Verify user is still active
            user = self._load_user(user_id=payload.get('user_id'))
            if not user or not user.is_active:
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            self.logger.debug("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            self.logger.debug(f"Invalid JWT token: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error validating JWT token: {e}")
            return None
    
    def logout_user(self, session_id: str) -> bool:
        """Logout user by invalidating session"""
        try:
            # Delete session
            result = self._delete_session(session_id)
            
            if result:
                self._log_audit_event(
                    user_id=None,  # Will be extracted from session
                    action="user_logout",
                    resource_type="session",
                    resource_id=session_id,
                    success=True
                )
                return True
            else:
                self._log_audit_event(
                    user_id=None,
                    action="user_logout",
                    resource_type="session",
                    resource_id=session_id,
                    success=False,
                    details={"error": "Session not found"}
                )
                return False
                
        except Exception as e:
            self.logger.error(f"Error logging out session {session_id}: {e}")
            return False
    
    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Change user password"""
        try:
            # Load user
            user = self._load_user(user_id=user_id)
            if not user:
                raise UserManagerError("User not found")
            
            # Verify old password
            if not self._verify_password(old_password, user.password_hash):
                self._log_audit_event(
                    user_id=user_id,
                    action="password_change",
                    resource_type="user",
                    resource_id=user_id,
                    success=False,
                    details={"error": "Invalid old password"}
                )
                return False
            
            # Validate new password strength
            is_strong, message = self._validate_password_strength(new_password)
            if not is_strong:
                self._log_audit_event(
                    user_id=user_id,
                    action="password_change",
                    resource_type="user",
                    resource_id=user_id,
                    success=False,
                    details={"error": f"Weak password: {message}"}
                )
                raise UserManagerError(f"Weak password: {message}")
            
            # Hash new password
            new_password_hash = self._hash_password(new_password)
            
            # Update user
            user.password_hash = new_password_hash
            user.last_login = datetime.utcnow()  # Reset to force re-authentication
            
            # Save user
            if self._save_user(user):
                self._log_audit_event(
                    user_id=user_id,
                    action="password_change",
                    resource_type="user",
                    resource_id=user_id,
                    success=True
                )
                return True
            else:
                self._log_audit_event(
                    user_id=user_id,
                    action="password_change",
                    resource_type="user",
                    resource_id=user_id,
                    success=False,
                    details={"error": "Failed to save user"}
                )
                return False
                
        except Exception as e:
            self.logger.error(f"Error changing password for user {user_id}: {e}")
            raise UserManagerError(f"Password change failed: {str(e)}")
    
    def generate_api_key(self, user_id: str) -> Optional[str]:
        """Generate API key for user"""
        try:
            if not self.config.enable_api_keys:
                raise UserManagerError("API key generation is disabled")
            
            # Load user
            user = self._load_user(user_id=user_id)
            if not user:
                raise UserManagerError("User not found")
            
            # Generate API key
            api_key = self._generate_api_key()
            api_key_hash = self._hash_api_key(api_key)
            
            # Update user
            user.api_key_hash = api_key_hash
            
            # Save user
            if self._save_user(user):
                self._log_audit_event(
                    user_id=user_id,
                    action="api_key_generate",
                    resource_type="user",
                    resource_id=user_id,
                    success=True
                )
                return api_key
            else:
                self._log_audit_event(
                    user_id=user_id,
                    action="api_key_generate",
                    resource_type="user",
                    resource_id=user_id,
                    success=False,
                    details={"error": "Failed to save user"}
                )
                return None
                
        except Exception as e:
            self.logger.error(f"Error generating API key for user {user_id}: {e}")
            raise UserManagerError(f"API key generation failed: {str(e)}")
    
    def validate_api_key(self, api_key: str) -> Optional[User]:
        """Validate API key and return user"""
        try:
            if not self.config.enable_api_keys:
                return None
            
            # Hash API key for comparison
            api_key_hash = self._hash_api_key(api_key)
            
            # Find user with matching API key hash
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT user_id FROM users WHERE api_key_hash = ? AND is_active = TRUE', 
                              (api_key_hash,))
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                user_id = row[0]
                return self._load_user(user_id=user_id)
                
        except Exception as e:
            self.logger.error(f"Error validating API key: {e}")
            return None
    
    def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """Get user permissions"""
        try:
            user = self._load_user(user_id=user_id)
            if not user:
                return set()
            
            return user.permissions
            
        except Exception as e:
            self.logger.error(f"Error getting permissions for user {user_id}: {e}")
            return set()
    
    def has_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if user has specific permission"""
        try:
            user_permissions = self.get_user_permissions(user_id)
            return permission in user_permissions
            
        except Exception as e:
            self.logger.error(f"Error checking permission for user {user_id}: {e}")
            return False
    
    def update_user(self, user_id: str, username: Optional[str] = None,
                   email: Optional[str] = None, role: Optional[UserRole] = None,
                   permissions: Optional[Set[Permission]] = None,
                   is_active: Optional[bool] = None) -> bool:
        """Update user information"""
        try:
            # Load user
            user = self._load_user(user_id=user_id)
            if not user:
                raise UserManagerError("User not found")
            
            # Update fields
            if username is not None:
                user.username = username
            if email is not None:
                user.email = email
            if role is not None:
                user.role = role
            if permissions is not None:
                user.permissions = permissions
            if is_active is not None:
                user.is_active = is_active
            
            # Save user
            if self._save_user(user):
                self._log_audit_event(
                    user_id=user_id,
                    action="user_update",
                    resource_type="user",
                    resource_id=user_id,
                    success=True,
                    details={"updated_fields": [k for k, v in locals().items() if v is not None and k != 'user_id']}
                )
                return True
            else:
                self._log_audit_event(
                    user_id=user_id,
                    action="user_update",
                    resource_type="user",
                    resource_id=user_id,
                    success=False,
                    details={"error": "Failed to save user"}
                )
                return False
                
        except Exception as e:
            self.logger.error(f"Error updating user {user_id}: {e}")
            raise UserManagerError(f"User update failed: {str(e)}")
    
    def delete_user(self, user_id: str) -> bool:
        """Delete user"""
        try:
            # Load user
            user = self._load_user(user_id=user_id)
            if not user:
                raise UserManagerError("User not found")
            
            # Delete user sessions first
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM user_sessions WHERE user_id = ?', (user_id,))
                conn.commit()
            
            # Delete user
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
                affected_rows = cursor.rowcount
                conn.commit()
            
            if affected_rows > 0:
                self._log_audit_event(
                    user_id=user_id,
                    action="user_delete",
                    resource_type="user",
                    resource_id=user_id,
                    success=True
                )
                self.logger.info(f"User deleted: {user.username}")
                return True
            else:
                self._log_audit_event(
                    user_id=user_id,
                    action="user_delete",
                    resource_type="user",
                    resource_id=user_id,
                    success=False,
                    details={"error": "User not found"}
                )
                return False
                
        except Exception as e:
            self.logger.error(f"Error deleting user {user_id}: {e}")
            raise UserManagerError(f"User deletion failed: {str(e)}")
    
    def list_users(self) -> List[Dict[str, Any]]:
        """List all users"""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT user_id, username, email, role, is_active, created_at, last_login
                    FROM users
                    ORDER BY created_at DESC
                ''')
                
                rows = cursor.fetchall()
                users = []
                
                for row in rows:
                    users.append({
                        'user_id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'role': row[3],
                        'is_active': bool(row[4]),
                        'created_at': row[5],
                        'last_login': row[6]
                    })
                
                return users
                
        except Exception as e:
            self.logger.error(f"Error listing users: {e}")
            return []
    
    def get_audit_log(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get audit log entries"""
        try:
            if not self.config.enable_audit_logging:
                return []
            
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, timestamp, user_id, action, resource_type, resource_id,
                           ip_address, user_agent, success, details
                    FROM audit_log
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
                
                rows = cursor.fetchall()
                audit_entries = []
                
                for row in rows:
                    audit_entries.append({
                        'id': row[0],
                        'timestamp': row[1],
                        'user_id': row[2],
                        'action': row[3],
                        'resource_type': row[4],
                        'resource_id': row[5],
                        'ip_address': row[6],
                        'user_agent': row[7],
                        'success': bool(row[8]),
                        'details': json.loads(row[9]) if row[9] else None
                    })
                
                return audit_entries
                
        except Exception as e:
            self.logger.error(f"Error getting audit log: {e}")
            return []
    
    def _start_background_tasks(self):
        """Start background maintenance tasks"""
        # Session cleanup task
        if self.config.enable_session_cleanup:
            cleanup_task = asyncio.create_task(self._session_cleanup_task())
            self.background_tasks.add(cleanup_task)
            cleanup_task.add_done_callback(self.background_tasks.discard)
        
        # Audit log cleanup task
        if self.config.enable_audit_logging:
            audit_cleanup_task = asyncio.create_task(self._audit_log_cleanup_task())
            self.background_tasks.add(audit_cleanup_task)
            audit_cleanup_task.add_done_callback(self.background_tasks.discard)
    
    async def _session_cleanup_task(self):
        """Background task to clean up expired sessions"""
        try:
            while True:
                try:
                    # Delete expired sessions
                    with self._get_db_connection() as conn:
                        cursor = conn.cursor()
                        
                        cursor.execute('''
                            DELETE FROM user_sessions 
                            WHERE expires_at < ?
                        ''', (datetime.utcnow().isoformat(),))
                        
                        deleted_count = cursor.rowcount
                        conn.commit()
                        
                        if deleted_count > 0:
                            self.logger.debug(f"Cleaned up {deleted_count} expired sessions")
                    
                    # Wait for next cleanup interval
                    await asyncio.sleep(self.config.session_cleanup_interval_minutes * 60)
                    
                except asyncio.CancelledError:
                    self.logger.info("Session cleanup task cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"Error in session cleanup task: {e}")
                    await asyncio.sleep(60)  # Wait before retrying
                    
        except Exception as e:
            self.logger.error(f"Fatal error in session cleanup task: {e}")
    
    async def _audit_log_cleanup_task(self):
        """Background task to clean up old audit log entries"""
        try:
            while True:
                try:
                    if not self.config.enable_audit_logging:
                        await asyncio.sleep(3600)  # Check every hour
                        continue
                    
                    # Calculate cutoff date
                    cutoff_date = (datetime.utcnow() - timedelta(
                        days=self.config.audit_log_retention_days
                    )).isoformat()
                    
                    # Delete old audit log entries
                    with self._get_db_connection() as conn:
                        cursor = conn.cursor()
                        
                        cursor.execute('''
                            DELETE FROM audit_log 
                            WHERE timestamp < ?
                        ''', (cutoff_date,))
                        
                        deleted_count = cursor.rowcount
                        conn.commit()
                        
                        if deleted_count > 0:
                            self.logger.info(f"Cleaned up {deleted_count} old audit log entries")
                    
                    # Wait for next cleanup interval (daily)
                    await asyncio.sleep(86400)
                    
                except asyncio.CancelledError:
                    self.logger.info("Audit log cleanup task cancelled")
                    break
                except Exception as e:
                    self.logger.error(f"Error in audit log cleanup task: {e}")
                    await asyncio.sleep(3600)  # Wait before retrying
                    
        except Exception as e:
            self.logger.error(f"Fatal error in audit log cleanup task: {e}")
    
    def close(self):
        """Close user manager and cleanup resources"""
        try:
            # Cancel background tasks
            for task in self.background_tasks:
                task.cancel()
            
            self.logger.info("User manager closed")
            
        except Exception as e:
            self.logger.error(f"Error closing user manager: {e}")

# Decorators for access control
def require_permission(permission: Permission):
    """Decorator to require specific permission for function execution"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # This would typically check user session/permissions
            # For now, we'll just pass through
            return func(*args, **kwargs)
        return wrapper
    return decorator

def require_role(role: UserRole):
    """Decorator to require specific role for function execution"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # This would typically check user role
            # For now, we'll just pass through
            return func(*args, **kwargs)
        return wrapper
    return decorator

def require_authentication(func):
    """Decorator to require authentication for function execution"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # This would typically check user authentication
        # For now, we'll just pass through
        return func(*args, **kwargs)
    return wrapper

# Example usage and testing
if __name__ == "__main__":
    import tempfile
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create user configuration
        user_config = UserConfig(
            db_path=str(temp_path / "test_users.db"),
            password_hash_algorithm="argon2",
            password_min_length=8,
            enable_two_factor_auth=False,
            enable_audit_logging=True,
            audit_log_retention_days=7
        )
        
        print("👥 User Management System Demo")
        print("=" * 40)
        
        # Initialize user manager
        try:
            user_manager = UserManager(user_config)
            print("✅ User manager initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize user manager: {e}")
            exit(1)
        
        # Test user creation
        print("\n1. Testing user creation...")
        try:
            new_user = user_manager.create_user(
                username="testuser",
                email="test@example.com",
                password="SecurePass123!",
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
            auth_result = user_manager.authenticate_user(
                username="testuser",
                password="SecurePass123!",
                ip_address="127.0.0.1",
                user_agent="Test Client"
            )
            
            if auth_result:
                print("✅ User authenticated successfully")
                print(f"   JWT Token: {auth_result['jwt_token'][:20]}...")
                print(f"   Session ID: {auth_result['session']['session_id'][:10]}...")
                print(f"   Expires at: {auth_result['expires_at']}")
                
                session_id = auth_result['session']['session_id']
                jwt_token = auth_result['jwt_token']
            else:
                print("❌ User authentication failed")
                session_id = None
                jwt_token = None
                
        except Exception as e:
            print(f"❌ User authentication failed: {e}")
            session_id = None
            jwt_token = None
        
        # Test session validation
        print("\n3. Testing session validation...")
        if session_id:
            try:
                user = user_manager.validate_session(session_id)
                if user:
                    print("✅ Session validated successfully")
                    print(f"   Username: {user.username}")
                    print(f"   Role: {user.role.value}")
                else:
                    print("❌ Session validation failed")
                    
            except Exception as e:
                print(f"❌ Session validation failed: {e}")
        
        # Test JWT token validation
        print("\n4. Testing JWT token validation...")
        if jwt_token:
            try:
                payload = user_manager.validate_jwt_token(jwt_token)
                if payload:
                    print("✅ JWT token validated successfully")
                    print(f"   Username: {payload.get('username')}")
                    print(f"   Role: {payload.get('role')}")
                    print(f"   Expires: {payload.get('exp')}")
                else:
                    print("❌ JWT token validation failed")
                    
            except Exception as e:
                print(f"❌ JWT token validation failed: {e}")
        
        # Test user permissions
        print("\n5. Testing user permissions...")
        try:
            # Get user ID for created user
            users = user_manager.list_users()
            if users:
                user_id = users[0]['user_id']
                
                permissions = user_manager.get_user_permissions(user_id)
                print("✅ User permissions retrieved successfully")
                print(f"   Permissions: {[p.value for p in permissions]}")
                
                has_report_perm = user_manager.has_permission(user_id, Permission.REPORT_READ)
                print(f"   Has report read permission: {has_report_perm}")
                
                has_admin_perm = user_manager.has_permission(user_id, Permission.SYSTEM_ADMIN)
                print(f"   Has system admin permission: {has_admin_perm}")
            else:
                print("❌ No users found for permission testing")
                
        except Exception as e:
            print(f"❌ User permissions test failed: {e}")
        
        # Test audit log
        print("\n6. Testing audit log...")
        try:
            audit_entries = user_manager.get_audit_log(limit=10)
            print("✅ Audit log retrieved successfully")
            print(f"   Entries found: {len(audit_entries)}")
            
            if audit_entries:
                latest_entry = audit_entries[0]
                print(f"   Latest entry: {latest_entry['action']} at {latest_entry['timestamp']}")
                
        except Exception as e:
            print(f"❌ Audit log test failed: {e}")
        
        # Test user listing
        print("\n7. Testing user listing...")
        try:
            users = user_manager.list_users()
            print("✅ User listing successful")
            print(f"   Users found: {len(users)}")
            
            for user in users[:3]:  # Show first 3 users
                print(f"   - {user['username']} ({user['role']}) - Active: {user['is_active']}")
                
        except Exception as e:
            print(f"❌ User listing failed: {e}")
        
        # Test password change
        print("\n8. Testing password change...")
        if user_id:
            try:
                result = user_manager.change_password(
                    user_id=user_id,
                    old_password="SecurePass123!",
                    new_password="NewSecurePass456!"
                )
                
                if result:
                    print("✅ Password changed successfully")
                else:
                    print("❌ Password change failed")
                    
            except Exception as e:
                print(f"❌ Password change failed: {e}")
        
        # Test API key generation
        print("\n9. Testing API key generation...")
        if user_id:
            try:
                api_key = user_manager.generate_api_key(user_id)
                if api_key:
                    print("✅ API key generated successfully")
                    print(f"   API Key: {api_key[:10]}...")
                    
                    # Test API key validation
                    validated_user = user_manager.validate_api_key(api_key)
                    if validated_user:
                        print("✅ API key validated successfully")
                        print(f"   Username: {validated_user.username}")
                    else:
                        print("❌ API key validation failed")
                else:
                    print("❌ API key generation failed")
                    
            except Exception as e:
                print(f"❌ API key test failed: {e}")
        
        # Cleanup
        user_manager.close()
        
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