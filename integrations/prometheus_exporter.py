#!/usr/bin/env python3

# Prometheus Exporter for Enterprise Reporting System
# Exposes collected metrics in Prometheus format

import json
import os
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from prometheus_client import CollectorRegistry, Gauge, generate_latest, CONTENT_TYPE_LATEST
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
import glob

class ReportsCollector:
    """
    A custom collector for the Enterprise Reporting System metrics
    """
    
    def __init__(self, data_dir="/home/cbwinslow/reports/data"):
        self.data_dir = data_dir
        
    def collect(self):
        """Collect metrics from report files and yield to Prometheus"""
        
        # Create gauge metrics
        system_cpu_usage = GaugeMetricFamily(
            'reports_system_cpu_usage_percent',
            'CPU usage percentage',
            labels=['hostname']
        )
        
        system_memory_usage = GaugeMetricFamily(
            'reports_system_memory_usage_percent',
            'Memory usage percentage',
            labels=['hostname']
        )
        
        filesystem_usage = GaugeMetricFamily(
            'reports_filesystem_usage_percent',
            'Filesystem usage percentage',
            labels=['hostname', 'mount_point']
        )
        
        # Process collected report files
        report_files = glob.glob(os.path.join(self.data_dir, "system_info_*.json"))
        
        for report_file in report_files:
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                
                hostname = report_data.get('hostname', 'unknown')
                
                # Extract system metrics if available
                if 'cpu' in report_data:
                    cpu_percent = report_data['cpu'].get('usage_percent')
                    if cpu_percent is not None:
                        system_cpu_usage.add_metric([hostname], float(cpu_percent))
                
                if 'memory' in report_data:
                    mem_percent = report_data['memory'].get('usage_percent')
                    if mem_percent is not None:
                        system_memory_usage.add_metric([hostname], float(mem_percent))
                
                # Extract filesystem metrics
                if 'filesystems' in report_data:
                    for fs in report_data['filesystems']:
                        mount_point = fs.get('mount_point', 'unknown')
                        usage_percent = fs.get('usage_percent', 0)
                        filesystem_usage.add_metric([hostname, mount_point], float(usage_percent))
                        
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                print(f"Error processing report file {report_file}: {e}")
                continue
        
        yield system_cpu_usage
        yield system_memory_usage
        yield filesystem_usage

class MetricsHandler(BaseHTTPRequestHandler):
    """
    HTTP handler for Prometheus metrics endpoint
    """
    
    def do_GET(self):
        if self.path == '/metrics':
            # Collect current metrics
            registry = CollectorRegistry()
            registry.register(ReportsCollector())
            
            # Generate latest metrics output
            metrics_output = generate_latest(registry)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE_LATEST)
            self.end_headers()
            self.wfile.write(metrics_output)
        elif self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>Enterprise Reporting System Prometheus Exporter</h1><p><a href="/metrics">Metrics</a></p></body></html>')
        else:
            self.send_response(404)
            self.end_headers()

def run_exporter(port=9090):
    """
    Run the Prometheus exporter server
    """
    print(f"Starting Prometheus exporter on port {port}")
    
    server = HTTPServer(('0.0.0.0', port), MetricsHandler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Prometheus exporter...")
        server.shutdown()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Enterprise Reporting System Prometheus Exporter')
    parser.add_argument('--port', type=int, default=9090, help='Port to run the exporter on (default: 9090)')
    parser.add_argument('--data-dir', type=str, default='/home/cbwinslow/reports/data', 
                        help='Directory containing report files (default: /home/cbwinslow/reports/data)')
    
    args = parser.parse_args()
    
    # Add the collector to the default registry
    from prometheus_client import REGISTRY
    REGISTRY.register(ReportsCollector(args.data_dir))
    
    # Run the server
    run_exporter(args.port)