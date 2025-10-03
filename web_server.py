#!/usr/bin/env python3

# Simple Web Server for Enterprise Reporting System Dashboard
# Serves the web interface and provides API endpoints

import os
import json
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import mimetypes
import time
import logging
from datetime import datetime, timedelta

class DashboardHandler(SimpleHTTPRequestHandler):
    """Custom request handler for the dashboard"""
    
    def __init__(self, *args, **kwargs):
        # Set the directory to serve from
        self.base_dir = Path('/home/cbwinslow/reports/web')
        super().__init__(*args, directory=str(self.base_dir), **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        
        # API endpoints
        if parsed_path.path.startswith('/api/'):
            self.handle_api_request(parsed_path)
        else:
            # Serve static files
            super().do_GET()
    
    def handle_api_request(self, parsed_path):
        """Handle API requests"""
        path_parts = parsed_path.path.strip('/').split('/')
        
        if len(path_parts) >= 3 and path_parts[1] == 'api' and path_parts[2] == 'v1':
            if path_parts[3] == 'reports':
                self.handle_reports_api(parsed_path.query)
            elif path_parts[3] == 'systems':
                self.handle_systems_api()
            elif path_parts[3] == 'metrics':
                self.handle_metrics_api()
            else:
                self.send_error(404, "API endpoint not found")
        else:
            self.send_error(404, "API endpoint not found")
    
    def handle_reports_api(self, query_string):
        """Handle reports API endpoint"""
        # Parse query parameters
        params = parse_qs(query_string)
        report_type = params.get('type', ['all'])[0]
        time_range = params.get('timeRange', ['last24h'])[0]
        
        # In a real implementation, this would query the actual report data
        # For demo, we'll return mock data
        mock_reports = [
            {
                "id": 1,
                "hostname": "server1.example.com",
                "type": "system",
                "timestamp": datetime.utcnow().isoformat(),
                "status": "success",
                "data": {
                    "cpu_usage_percent": 15.2,
                    "memory_usage_percent": 42.7,
                    "disk_usage_percent": 78.3
                }
            },
            {
                "id": 2,
                "hostname": "server2.example.com", 
                "type": "network",
                "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                "status": "success",
                "data": {
                    "bandwidth_in_mb": 125.5,
                    "connections": 42,
                    "errors": 0
                }
            },
            {
                "id": 3,
                "hostname": "server3.example.com",
                "type": "filesystem", 
                "timestamp": (datetime.utcnow() - timedelta(minutes=10)).isoformat(),
                "status": "warning",
                "data": {
                    "disk_usage_percent": 89.2,
                    "inodes_usage_percent": 65.1
                }
            }
        ]
        
        # Filter by type if specified
        if report_type != 'all':
            filtered_reports = [r for r in mock_reports if r['type'] == report_type]
        else:
            filtered_reports = mock_reports
        
        response = {
            "data": filtered_reports,
            "pagination": {
                "page": 1,
                "limit": 20,
                "total": len(filtered_reports)
            }
        }
        
        self.send_json_response(response)
    
    def handle_systems_api(self):
        """Handle systems API endpoint"""
        # Mock system data
        mock_systems = [
            {
                "id": 1,
                "hostname": "server1.example.com",
                "status": "active",
                "type": "physical",
                "last_report": (datetime.utcnow() - timedelta(minutes=2)).isoformat(),
                "os": "Ubuntu 20.04",
                "cpu_count": 8,
                "memory_gb": 32
            },
            {
                "id": 2,
                "hostname": "server2.example.com", 
                "status": "active",
                "type": "virtual",
                "last_report": (datetime.utcnow() - timedelta(minutes=3)).isoformat(),
                "os": "CentOS 7",
                "cpu_count": 4,
                "memory_gb": 16
            },
            {
                "id": 3,
                "hostname": "server3.example.com",
                "status": "warning",
                "type": "physical",
                "last_report": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
                "os": "Ubuntu 18.04", 
                "cpu_count": 16,
                "memory_gb": 64
            }
        ]
        
        response = {
            "data": mock_systems,
            "total": len(mock_systems)
        }
        
        self.send_json_response(response)
    
    def handle_metrics_api(self):
        """Handle metrics API endpoint"""
        # Mock metrics data
        metrics = {
            "summary": {
                "total_systems": 12,
                "total_reports": 145,
                "active_alerts": 3,
                "success_rate": 97.8
            },
            "charts": {
                "performance": [
                    {"time": (datetime.utcnow() - timedelta(minutes=i)).isoformat(), 
                     "cpu": round(10 + (i * 2) % 30, 1),
                     "memory": round(20 + (i * 3) % 50, 1),
                     "disk": round(70 + (i * 1) % 15, 1)}
                    for i in range(10, -1, -1)
                ],
                "status_breakdown": {
                    "success": 130,
                    "failed": 3,
                    "pending": 12
                },
                "system_types": {
                    "physical": 8,
                    "virtual": 4,
                    "container": 0
                }
            }
        }
        
        self.send_json_response(metrics)
    
    def send_json_response(self, data):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        json_data = json.dumps(data, indent=2)
        self.wfile.write(json_data.encode('utf-8'))
    
    def end_headers(self):
        """Add CORS headers"""
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

class DashboardServer:
    """Dashboard server class"""
    
    def __init__(self, host='localhost', port=8081):
        self.host = host
        self.port = port
        self.httpd = None
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start the dashboard server"""
        try:
            self.httpd = HTTPServer((self.host, self.port), DashboardHandler)
            self.logger.info(f"Dashboard server starting on {self.host}:{self.port}")
            self.logger.info(f"Serving dashboard from /home/cbwinslow/reports/web")
            print(f"Dashboard available at: http://{self.host}:{self.port}")
            print("Press Ctrl+C to stop the server")
            
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            self.logger.info("Shutting down dashboard server...")
            self.httpd.shutdown()
        except Exception as e:
            self.logger.error(f"Error starting dashboard server: {e}")
            raise
    
    def stop(self):
        """Stop the dashboard server"""
        if self.httpd:
            self.httpd.shutdown()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Enterprise Reporting Dashboard Server')
    parser.add_argument('--host', type=str, default='localhost',
                        help='Host to bind the dashboard server (default: localhost)')
    parser.add_argument('--port', type=int, default=8081,
                        help='Port to bind the dashboard server (default: 8081)')
    
    args = parser.parse_args()
    
    server = DashboardServer(host=args.host, port=args.port)
    server.start()

if __name__ == "__main__":
    main()