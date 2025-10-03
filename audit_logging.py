#!/usr/bin/env python3

# Comprehensive Logging and Audit Trail System for Enterprise Reporting System
# Provides detailed logging, audit trails, and compliance tracking

import json
import os
import logging
import logging.handlers
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import hmac
import threading
from typing import Dict, Any, Optional, List
import sqlite3
from contextlib import contextmanager
import secrets

class AuditLogger:
    """Main audit logging system"""
    
    def __init__(self, log_dir: str = "/home/cbwinslow/reports/logs", 
                 db_path: str = "/home/cbwinslow/reports/audit.db"):
        self.log_dir = Path(log_dir)
        self.db_path = Path(db_path)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize the audit database
        self.init_database()
        
        # Set up logging
        self.logger = self.setup_logger()
        
        # Thread lock for safe database access
        self.db_lock = threading.Lock()
        
        # Initialize HMAC key for log integrity
        self.hmac_key = os.getenv('AUDIT_HMAC_KEY', secrets.token_urlsafe(32)).encode('utf-8')
    
    def setup_logger(self) -> logging.Logger:
        """Set up the audit logger"""
        logger = logging.getLogger('audit')
        logger.setLevel(logging.INFO)
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler for audit logs
        audit_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / 'audit.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        audit_handler.setFormatter(formatter)
        logger.addHandler(audit_handler)
        
        # Console handler for debugging (optional)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def init_database(self):
        """Initialize the audit database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create audit trail table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_trail (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    user TEXT,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    session_id TEXT,
                    hmac_signature TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create index for faster queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_trail(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON audit_trail(event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_user ON audit_trail(user)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_resource ON audit_trail(resource_type, resource_id)')
            
            conn.commit()
    
    def generate_hmac_signature(self, data: Dict[str, Any]) -> str:
        """Generate HMAC signature for log integrity"""
        # Create a consistent string representation of the data
        data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        signature = hmac.new(
            self.hmac_key,
            data_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def log_event(self, event_type: str, action: str, user: str = "system", 
                  resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                  details: Optional[Dict[str, Any]] = None, 
                  ip_address: Optional[str] = None, 
                  user_agent: Optional[str] = None,
                  session_id: Optional[str] = None) -> bool:
        """Log an audit event"""
        try:
            timestamp = datetime.utcnow().isoformat()
            
            # Prepare log data
            log_data = {
                "timestamp": timestamp,
                "event_type": event_type,
                "user": user,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "details": json.dumps(details) if details else None,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "session_id": session_id
            }
            
            # Generate HMAC signature for integrity
            hmac_signature = self.generate_hmac_signature(log_data)
            log_data["hmac_signature"] = hmac_signature
            
            # Insert into database
            with self.db_lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO audit_trail 
                        (timestamp, event_type, user, action, resource_type, resource_id, 
                         details, ip_address, user_agent, session_id, hmac_signature)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        log_data["timestamp"], log_data["event_type"], log_data["user"],
                        log_data["action"], log_data["resource_type"], log_data["resource_id"],
                        log_data["details"], log_data["ip_address"], log_data["user_agent"],
                        log_data["session_id"], log_data["hmac_signature"]
                    ))
                    conn.commit()
            
            # Log to file as well
            self.logger.info(f"AUDIT: {event_type} - {action} by {user}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to log audit event: {e}")
            return False
    
    def log_report_collection(self, hostname: str, report_type: str, 
                            success: bool, duration: float, details: Optional[Dict] = None) -> bool:
        """Log report collection event"""
        action = f"{'COLLECTED' if success else 'FAILED'}_REPORT"
        details = details or {}
        details.update({
            "hostname": hostname,
            "report_type": report_type,
            "duration": duration
        })
        
        return self.log_event(
            event_type="REPORT_COLLECTION",
            action=action,
            resource_type="REPORT",
            resource_id=f"{hostname}:{report_type}",
            details=details
        )
    
    def log_api_access(self, endpoint: str, user: str, ip_address: str, 
                      method: str = "GET", success: bool = True, 
                      response_time: float = 0.0) -> bool:
        """Log API access event"""
        action = f"API_ACCESS_{method}_{'SUCCESS' if success else 'FAILED'}"
        details = {
            "endpoint": endpoint,
            "method": method,
            "response_time": response_time
        }
        
        return self.log_event(
            event_type="API_ACCESS",
            action=action,
            user=user,
            resource_type="API_ENDPOINT",
            resource_id=endpoint,
            details=details,
            ip_address=ip_address
        )
    
    def log_config_change(self, user: str, config_path: str, 
                         old_value: Any, new_value: Any) -> bool:
        """Log configuration change event"""
        details = {
            "config_path": config_path,
            "old_value": old_value,
            "new_value": new_value
        }
        
        return self.log_event(
            event_type="CONFIG_CHANGE",
            action="CONFIG_UPDATED",
            user=user,
            resource_type="CONFIG",
            resource_id=config_path,
            details=details
        )
    
    def log_authentication(self, user: str, ip_address: str, 
                          success: bool, auth_method: str = "API_KEY") -> bool:
        """Log authentication event"""
        action = f"AUTHENTICATION_{'SUCCESS' if success else 'FAILED'}"
        details = {
            "auth_method": auth_method
        }
        
        return self.log_event(
            event_type="AUTHENTICATION",
            action=action,
            user=user,
            resource_type="USER",
            resource_id=user,
            details=details,
            ip_address=ip_address
        )
    
    def query_audit_trail(self, event_type: Optional[str] = None, 
                         user: Optional[str] = None,
                         start_date: Optional[datetime] = None,
                         end_date: Optional[datetime] = None,
                         limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Query audit trail with filters"""
        with self.db_lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row  # Enable column access by name
                cursor = conn.cursor()
                
                query = "SELECT * FROM audit_trail WHERE 1=1"
                params = []
                
                if event_type:
                    query += " AND event_type = ?"
                    params.append(event_type)
                
                if user:
                    query += " AND user = ?"
                    params.append(user)
                
                if start_date:
                    query += " AND timestamp >= ?"
                    params.append(start_date.isoformat())
                
                if end_date:
                    query += " AND timestamp <= ?"
                    params.append(end_date.isoformat())
                
                query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                # Convert rows to dictionaries
                results = [dict(row) for row in rows]
                return results
    
    def get_user_activity(self, user: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get activity for a specific user"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        return self.query_audit_trail(
            user=user,
            start_date=start_date,
            end_date=end_date
        )
    
    def get_report_collection_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get statistics about report collection"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        with self.db_lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total events
                cursor.execute('''
                    SELECT COUNT(*) as total
                    FROM audit_trail
                    WHERE event_type = 'REPORT_COLLECTION'
                    AND timestamp >= ?
                    AND timestamp <= ?
                ''', (start_date.isoformat(), end_date.isoformat()))
                total = cursor.fetchone()['total']
                
                # Successful collections
                cursor.execute('''
                    SELECT COUNT(*) as successful
                    FROM audit_trail
                    WHERE event_type = 'REPORT_COLLECTION'
                    AND action = 'COLLECTED_REPORT'
                    AND timestamp >= ?
                    AND timestamp <= ?
                ''', (start_date.isoformat(), end_date.isoformat()))
                successful = cursor.fetchone()['successful']
                
                # Failed collections
                failed = total - successful
                
                # Success rate
                success_rate = (successful / total * 100) if total > 0 else 0
                
                # Top hosts
                cursor.execute('''
                    SELECT resource_id, COUNT(*) as count
                    FROM audit_trail
                    WHERE event_type = 'REPORT_COLLECTION'
                    AND timestamp >= ?
                    AND timestamp <= ?
                    GROUP BY resource_id
                    ORDER BY count DESC
                    LIMIT 10
                ''', (start_date.isoformat(), end_date.isoformat()))
                top_hosts = cursor.fetchall()
                
                return {
                    "total_collections": total,
                    "successful_collections": successful,
                    "failed_collections": failed,
                    "success_rate": round(success_rate, 2),
                    "top_hosts": [{"host": row['resource_id'], "count": row['count']} for row in top_hosts]
                }
    
    def verify_log_integrity(self) -> bool:
        """Verify the integrity of logs using HMAC signatures"""
        with self.db_lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT * FROM audit_trail")
                rows = cursor.fetchall()
                
                for row in rows:
                    # Reconstruct the log data without the signature
                    log_data = {
                        "timestamp": row["timestamp"],
                        "event_type": row["event_type"],
                        "user": row["user"],
                        "action": row["action"],
                        "resource_type": row["resource_type"],
                        "resource_id": row["resource_id"],
                        "details": row["details"],
                        "ip_address": row["ip_address"],
                        "user_agent": row["user_agent"],
                        "session_id": row["session_id"]
                    }
                    
                    # Generate expected signature
                    expected_signature = self.generate_hmac_signature(log_data)
                    
                    # Compare with stored signature
                    if expected_signature != row["hmac_signature"]:
                        self.logger.error(f"Integrity check failed for log ID {row['id']}")
                        return False
                
                self.logger.info("All logs passed integrity verification")
                return True
    
    def export_audit_data(self, output_path: str, 
                         start_date: Optional[datetime] = None,
                         end_date: Optional[datetime] = None,
                         event_types: Optional[List[str]] = None) -> bool:
        """Export audit data to JSON file"""
        try:
            # Query data based on filters
            with self.db_lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    query = "SELECT * FROM audit_trail WHERE 1=1"
                    params = []
                    
                    if start_date:
                        query += " AND timestamp >= ?"
                        params.append(start_date.isoformat())
                    
                    if end_date:
                        query += " AND timestamp <= ?"
                        params.append(end_date.isoformat())
                    
                    if event_types:
                        placeholders = ','.join('?' * len(event_types))
                        query += f" AND event_type IN ({placeholders})"
                        params.extend(event_types)
                    
                    query += " ORDER BY timestamp DESC"
                    cursor.execute(query, params)
                    rows = cursor.fetchall()
                    
                    # Convert rows to list of dictionaries
                    audit_data = [dict(row) for row in rows]
            
            # Write to JSON file
            with open(output_path, 'w') as f:
                json.dump(audit_data, f, indent=2, default=str)
            
            self.logger.info(f"Audit data exported to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export audit data: {e}")
            return False
    
    def cleanup_old_logs(self, days_to_keep: int = 90) -> bool:
        """Remove audit logs older than specified days"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
            
            with self.db_lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "DELETE FROM audit_trail WHERE timestamp < ?",
                        (cutoff_date.isoformat(),)
                    )
                    deleted_count = cursor.rowcount
                    conn.commit()
            
            self.logger.info(f"Cleaned up {deleted_count} audit logs older than {days_to_keep} days")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {e}")
            return False


class LoggingManager:
    """High-level manager for application logging"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        
        # Set up application logger
        self.app_logger = logging.getLogger('reports_app')
        self.app_logger.setLevel(logging.INFO)
        
        # File handler for application logs
        handler = logging.handlers.RotatingFileHandler(
            '/home/cbwinslow/reports/logs/application.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.app_logger.addHandler(handler)
    
    def log_application_event(self, level: str, message: str, **kwargs):
        """Log an application event"""
        getattr(self.app_logger, level.lower())(message)
        
        # Also log to audit trail if it's an important event
        if level.upper() in ['ERROR', 'CRITICAL']:
            self.audit_logger.log_event(
                event_type="APPLICATION_ERROR",
                action=f"APP_{level.upper()}",
                resource_type="APPLICATION",
                details=kwargs
            )
    
    def log_report_processed(self, hostname: str, report_type: str, 
                           success: bool = True, duration: float = 0.0):
        """Log report processing event"""
        self.audit_logger.log_report_collection(
            hostname=hostname,
            report_type=report_type,
            success=success,
            duration=duration
        )
    
    def log_api_request(self, endpoint: str, user: str, ip: str, 
                       method: str, success: bool, response_time: float):
        """Log API request"""
        self.audit_logger.log_api_access(
            endpoint=endpoint,
            user=user,
            ip_address=ip,
            method=method,
            success=success,
            response_time=response_time
        )
    
    def log_config_updated(self, user: str, config_path: str, old_val: Any, new_val: Any):
        """Log configuration update"""
        self.audit_logger.log_config_change(user, config_path, old_val, new_val)
    
    def get_report_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get report collection statistics"""
        return self.audit_logger.get_report_collection_stats(days)


# Example usage
if __name__ == "__main__":
    import time
    
    # Initialize logging manager
    log_manager = LoggingManager()
    
    # Example: Log application events
    log_manager.log_application_event("INFO", "Application started", version="1.0.0")
    log_manager.log_application_event("WARNING", "Configuration setting deprecated", setting="old_param")
    
    # Example: Log report collection
    log_manager.log_report_processed("server1.example.com", "system", success=True, duration=0.5)
    log_manager.log_report_processed("server2.example.com", "network", success=False, duration=0.1)
    
    # Example: Log API request
    log_manager.log_api_request("/api/v1/reports", "admin", "192.168.1.100", "GET", True, 0.05)
    
    # Example: Log config update
    log_manager.log_config_updated("admin", "/general/retention_days", 30, 60)
    
    # Get statistics
    stats = log_manager.get_report_stats(7)
    print("Report Collection Statistics (last 7 days):")
    print(f"Total Collections: {stats['total_collections']}")
    print(f"Success Rate: {stats['success_rate']}%")
    print(f"Top Hosts: {stats['top_hosts'][:3]}")
    
    # Query specific audit events
    print("\nRecent API Access Events:")
    recent_api_events = log_manager.audit_logger.query_audit_trail(
        event_type="API_ACCESS",
        limit=5
    )
    for event in recent_api_events:
        print(f"  {event['timestamp']}: {event['action']} - {event['details']}")
    
    # Export audit data
    export_path = "/tmp/audit_export.json"
    if log_manager.audit_logger.export_audit_data(export_path):
        print(f"\nAudit data exported to {export_path}")
    
    # Verify log integrity
    integrity_ok = log_manager.audit_logger.verify_log_integrity()
    print(f"\nLog integrity verification: {'PASSED' if integrity_ok else 'FAILED'}")