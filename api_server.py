#!/usr/bin/env python3

# Enterprise Reporting System API
# RESTful API for programmatic access to collected reports

import json
import os
import time
import glob
import logging
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import mimetypes
import threading
import hashlib
import hmac
from functools import wraps

# Configuration
BASE_DIR = Path("/home/cbwinslow/reports")
DATA_DIR = BASE_DIR / "data"
CONFIG_FILE = BASE_DIR / "config.json"

class APIConfig:
    """Configuration management for the API"""
    
    def __init__(self, config_path=CONFIG_FILE):
        self.config_path = config_path
        self.config = self.load_config()
    
    def load_config(self):
        """Load API configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            # Set default values for API-specific settings
            api_defaults = {
                "api": {
                    "enabled": True,
                    "host": "0.0.0.0",
                    "port": 8080,
                    "auth": {
                        "enabled": True,
                        "api_keys": [],
                        "jwt_secret": "default_secret_change_this"
                    }
                }
            }
            
            # Merge with existing config
            for key, value in api_defaults.items():
                if key not in config:
                    config[key] = value
                elif isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        if subkey not in config[key]:
                            config[key][subkey] = subvalue
            
            return config
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """Return default configuration"""
        return {
            "api": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8080,
                "auth": {
                    "enabled": True,
                    "api_keys": [],
                    "jwt_secret": "default_secret_change_this"
                }
            },
            "general": {
                "output_dir": "/home/cbwinslow/reports/data",
                "retention_days": 30
            }
        }
    
    def get(self, path, default=None):
        """Get config value by dot notation path"""
        keys = path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value

class ReportManager:
    """Manage report files and operations"""
    
    def __init__(self, data_dir=DATA_DIR):
        self.data_dir = Path(data_dir)
    
    def list_reports(self, report_type=None, hostname=None, start_date=None, end_date=None, 
                     page=1, limit=20):
        """List reports with filtering and pagination"""
        pattern = f"{report_type}*" if report_type else "*"
        pattern = f"{self.data_dir}/{pattern}_info_*.json"
        
        report_files = glob.glob(pattern)
        reports = []
        
        for file_path in report_files:
            try:
                with open(file_path, 'r') as f:
                    report_data = json.load(f)
                
                # Apply filters
                if hostname and report_data.get('hostname') != hostname:
                    continue
                
                timestamp = report_data.get('timestamp')
                if timestamp:
                    report_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    
                    if start_date and report_time < start_date:
                        continue
                    if end_date and report_time > end_date:
                        continue
                
                # Format report for response
                reports.append({
                    "id": hashlib.md5(f"{file_path}{timestamp}".encode()).hexdigest()[:12],
                    "type": report_data.get('type', 'unknown'),
                    "hostname": report_data.get('hostname', 'unknown'),
                    "timestamp": timestamp,
                    "size_bytes": os.path.getsize(file_path),
                    "file_path": file_path
                })
            
            except (json.JSONDecodeError, KeyError) as e:
                continue
        
        # Sort by timestamp (newest first)
        reports.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Apply pagination
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_reports = reports[start_idx:end_idx]
        
        return {
            "data": paginated_reports,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": len(reports),
                "pages": (len(reports) + limit - 1) // limit
            }
        }
    
    def get_report(self, report_id):
        """Get a specific report by ID"""
        # Find the report file by ID (which is based on filename and timestamp)
        all_files = glob.glob(f"{self.data_dir}/*_info_*.json")
        
        for file_path in all_files:
            try:
                with open(file_path, 'r') as f:
                    report_data = json.load(f)
                
                timestamp = report_data.get('timestamp')
                calculated_id = hashlib.md5(f"{file_path}{timestamp}".encode()).hexdigest()[:12]
                
                if calculated_id == report_id:
                    return {
                        "id": calculated_id,
                        "type": report_data.get('type', 'unknown'),
                        "hostname": report_data.get('hostname', 'unknown'),
                        "timestamp": timestamp,
                        "data": report_data
                    }
            except (json.JSONDecodeError, KeyError):
                continue
        
        return None
    
    def delete_report(self, report_id):
        """Delete a report by ID"""
        # Find and delete the report file
        all_files = glob.glob(f"{self.data_dir}/*_info_*.json")
        
        for file_path in all_files:
            try:
                with open(file_path, 'r') as f:
                    report_data = json.load(f)
                
                timestamp = report_data.get('timestamp')
                calculated_id = hashlib.md5(f"{file_path}{timestamp}".encode()).hexdigest()[:12]
                
                if calculated_id == report_id:
                    os.remove(file_path)
                    return True
            except (json.JSONDecodeError, KeyError, OSError):
                continue
        
        return False

class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the API"""
    
    def __init__(self, *args, config=None, report_manager=None, **kwargs):
        self.config = config or APIConfig()
        self.report_manager = report_manager or ReportManager()
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path_parts = parsed_path.path.strip('/').split('/')
        
        # Authentication check
        if self.config.get('api.auth.enabled', True):
            auth_result = self.authenticate_request()
            if not auth_result:
                self.send_error(401, "Unauthorized")
                return
        
        # Route handling
        if path_parts[0] == 'api' and path_parts[1] == 'v1':
            # API endpoints
            if len(path_parts) >= 3:
                if path_parts[2] == 'reports':
                    self.handle_reports(path_parts[3:])
                elif path_parts[2] == 'report-types':
                    self.handle_report_types()
                elif path_parts[2] == 'systems':
                    self.handle_systems(path_parts[3:])
                elif path_parts[2] == 'config':
                    self.handle_config()
                elif path_parts[2] == 'health':
                    self.handle_health()
                elif path_parts[2] == 'status':
                    self.handle_status()
                else:
                    self.send_error(404)
            else:
                self.send_error(404)
        else:
            self.send_error(404)
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        parsed_path = urlparse(self.path)
        path_parts = parsed_path.path.strip('/').split('/')
        
        # Authentication check
        if self.config.get('api.auth.enabled', True):
            auth_result = self.authenticate_request()
            if not auth_result:
                self.send_error(401, "Unauthorized")
                return
        
        # Route handling
        if path_parts[0] == 'api' and path_parts[1] == 'v1' and path_parts[2] == 'reports':
            if len(path_parts) == 4:
                self.handle_delete_report(path_parts[3])
            else:
                self.send_error(400, "Bad Request")
        else:
            self.send_error(404)
    
    def authenticate_request(self):
        """Authenticate incoming requests"""
        # Check for API key in header
        api_key = self.headers.get('X-API-Key')
        if api_key:
            valid_keys = self.config.get('api.auth.api_keys', [])
            return api_key in valid_keys
        
        # Check for Authorization header (Bearer token)
        auth_header = self.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            # In a real implementation, you'd validate the JWT token
            # For now, we'll just check if it matches our secret
            jwt_secret = self.config.get('api.auth.jwt_secret', 'default_secret_change_this')
            # This is a simplified check - in real implementation, use proper JWT validation
            return len(token) > 10  # Basic check for token validity
        
        return False
    
    def handle_reports(self, sub_path):
        """Handle reports endpoint"""
        if len(sub_path) == 0:
            # GET /api/v1/reports - List reports
            params = parse_qs(urlparse(self.path).query)
            
            # Parse query parameters
            report_type = params.get('type', [None])[0]
            hostname = params.get('hostname', [None])[0]
            start_date_str = params.get('start_date', [None])[0]
            end_date_str = params.get('end_date', [None])[0]
            page = int(params.get('page', [1])[0])
            limit = min(int(params.get('limit', [20])[0]), 100)  # Max 100 per page
            
            # Parse dates
            start_date = datetime.fromisoformat(start_date_str) if start_date_str else None
            end_date = datetime.fromisoformat(end_date_str) if end_date_str else None
            
            # Get reports
            reports = self.report_manager.list_reports(
                report_type=report_type,
                hostname=hostname,
                start_date=start_date,
                end_date=end_date,
                page=page,
                limit=limit
            )
            
            self.send_json_response(reports)
        
        elif len(sub_path) == 1:
            # GET /api/v1/reports/{id} - Get specific report
            report_id = sub_path[0]
            report = self.report_manager.get_report(report_id)
            
            if report:
                self.send_json_response(report)
            else:
                self.send_error(404, "Report not found")
    
    def handle_delete_report(self, report_id):
        """Handle deleting a specific report"""
        if self.report_manager.delete_report(report_id):
            self.send_json_response({"success": True, "message": "Report deleted successfully"})
        else:
            self.send_error(404, "Report not found")
    
    def handle_report_types(self):
        """Handle report types endpoint"""
        # Get all configured report types
        report_types = self.config.get('report_types', {})
        types_list = []
        
        for name, config in report_types.items():
            types_list.append({
                "name": name,
                "description": f"{name} report type",
                "enabled": config.get('enabled', True),
                "schedule": config.get('schedule', 'unknown')
            })
        
        self.send_json_response({"data": types_list})
    
    def handle_systems(self, sub_path):
        """Handle systems endpoint"""
        if len(sub_path) == 0:
            # GET /api/v1/systems - List monitored systems
            # This would typically come from remote_server config
            remote_servers = self.config.get('remote_servers.servers', [])
            systems = []
            
            for server in remote_servers:
                systems.append({
                    "hostname": server.get('name', 'unknown'),
                    "status": "active",  # In a real implementation, check actual status
                    "last_report": None,  # Would come from report data
                    "type": "remote",
                    "ip_address": server.get('host', 'unknown')
                })
            
            self.send_json_response({"data": systems})
        
        elif len(sub_path) == 1:
            # GET /api/v1/systems/{hostname} - Get specific system details
            hostname = sub_path[0]
            # This would look up information about a specific system
            system_detail = {
                "hostname": hostname,
                "status": "active",
                "last_report": None,
                "type": "remote",
                "ip_address": "unknown",
                "reports": {
                    "total": 0,
                    "last_24h": 0,
                    "types": []
                }
            }
            
            # Look up reports for this hostname
            report_list = self.report_manager.list_reports(hostname=hostname)
            system_detail["reports"]["total"] = report_list["pagination"]["total"]
            
            # Get reports from last 24 hours
            yesterday = datetime.now() - timedelta(days=1)
            report_list_24h = self.report_manager.list_reports(
                hostname=hostname, start_date=yesterday
            )
            system_detail["reports"]["last_24h"] = report_list_24h["pagination"]["total"]
            
            self.send_json_response(system_detail)
    
    def handle_config(self):
        """Handle config endpoint"""
        # Return sanitized config (exclude sensitive information)
        full_config = self.config.config
        sanitized_config = {
            "general": full_config.get('general', {}),
            "report_types": full_config.get('report_types', {}),
            "remote_servers": {
                "enabled": full_config.get('remote_servers.enabled', False),
                "count": len(full_config.get('remote_servers.servers', []))
            }
        }
        
        self.send_json_response(sanitized_config)
    
    def handle_health(self):
        """Handle health check endpoint"""
        health_status = {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "uptime_seconds": int(time.time() - getattr(self.server, 'start_time', time.time()))
        }
        
        self.send_json_response(health_status)
    
    def handle_status(self):
        """Handle status endpoint"""
        # Count reports in the last 24 hours
        yesterday = datetime.now() - timedelta(days=1)
        all_reports = self.report_manager.list_reports(start_date=yesterday)
        
        status = {
            "status": "operational",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "api": "running",
                "collector": "running",  # Would be determined by checking actual collector status
                "storage": "healthy"
            },
            "stats": {
                "reports_collected": all_reports["pagination"]["total"],
                "systems_monitored": 0,  # Would come from remote_server config
                "api_requests_today": getattr(self.server, 'request_count', 0)  # Would be tracked
            }
        }
        
        self.send_json_response(status)
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        json_data = json.dumps(data, indent=2)
        self.wfile.write(json_data.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Log messages to file instead of stdout"""
        logging.info(f"{self.address_string()} - {format % args}")

class APIServer:
    """Main API server class"""
    
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.config = APIConfig()
        self.report_manager = ReportManager()
        self.httpd = None
        self.start_time = time.time()
        self.request_count = 0
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(BASE_DIR / 'api.log'),
                logging.StreamHandler()
            ]
        )
    
    def get_handler(self):
        """Get a bound handler with config and report manager"""
        def handler(*args, **kwargs):
            return APIHandler(
                *args, 
                config=self.config, 
                report_manager=self.report_manager, 
                **kwargs
            )
        return handler
    
    def start(self):
        """Start the API server"""
        handler = self.get_handler()
        
        try:
            self.httpd = HTTPServer((self.host, self.port), handler)
            self.httpd.start_time = self.start_time
            self.httpd.request_count = self.request_count
            
            logging.info(f"Starting API server on {self.host}:{self.port}")
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            logging.info("Shutting down API server...")
            self.httpd.shutdown()
    
    def stop(self):
        """Stop the API server"""
        if self.httpd:
            self.httpd.shutdown()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Enterprise Reporting System API')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='Host to bind the API server (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080,
                        help='Port to bind the API server (default: 8080)')
    parser.add_argument('--config', type=str, default=str(CONFIG_FILE),
                        help=f'Configuration file path (default: {CONFIG_FILE})')
    
    args = parser.parse_args()
    
    # Initialize and start API server
    api_server = APIServer(host=args.host, port=args.port)
    api_server.start()

if __name__ == "__main__":
    main()