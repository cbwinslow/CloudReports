#!/usr/bin/env python3

# Loki Integration for Enterprise Reporting System
# Forwards collected logs and events to Loki

import os
import json
import time
import requests
import gzip
from datetime import datetime
import glob
import logging

class LokiIntegration:
    """
    Loki integration for the Enterprise Reporting System
    """
    
    def __init__(self, loki_url="http://localhost:3100", 
                 username=None, password=None, 
                 api_key=None, labels=None, 
                 batch_size=100, batch_wait="5s"):
        self.loki_url = loki_url.rstrip('/')
        self.auth = None
        self.headers = {'Content-Type': 'application/json'}
        
        if username and password:
            self.auth = (username, password)
        elif api_key:
            self.headers['Authorization'] = f'Bearer {api_key}'
        
        self.labels = labels or {"job": "reports", "source": "enterprise-reporting"}
        self.batch_size = batch_size
        self.batch_wait = int(batch_wait.rstrip('s'))  # Remove 's' and convert to int
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        self.log_url = f"{self.loki_url}/loki/api/v1/push"
    
    def format_log_entry(self, report_data, log_level="info"):
        """
        Format a report entry for Loki ingestion
        """
        timestamp = report_data.get('timestamp', datetime.utcnow().isoformat() + 'Z')
        
        # Convert timestamp to nanoseconds for Loki
        if '.' in timestamp:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = datetime.fromisoformat(timestamp.replace('Z', ''))
        timestamp_ns = int(dt.timestamp() * 1e9)
        
        # Create log line from report data
        log_line = json.dumps(report_data, separators=(',', ':'))
        
        # Create stream entry
        stream_labels = self.labels.copy()
        stream_labels["hostname"] = report_data.get('hostname', 'unknown')
        stream_labels["report_type"] = report_data.get('type', 'unknown')
        stream_labels["level"] = log_level
        
        return {
            "streams": [{
                "stream": stream_labels,
                "values": [[str(timestamp_ns), log_line]]
            }]
        }
    
    def send_batch(self, streams_batch):
        """
        Send a batch of streams to Loki
        """
        payload = {"streams": streams_batch}
        
        try:
            response = requests.post(
                self.log_url,
                headers=self.headers,
                auth=self.auth,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 204:
                self.logger.info(f"Successfully sent batch of {len(streams_batch)} streams to Loki")
                return True
            else:
                self.logger.error(f"Failed to send to Loki: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error sending to Loki: {e}")
            return False
    
    def process_report_files(self, data_dir="/home/cbwinslow/reports/data", 
                           report_types=None, lookback_hours=1):
        """
        Process report files and send them to Loki
        """
        if report_types is None:
            report_types = ["system", "network", "filesystem", "error", "log", "container"]
        
        # Calculate time threshold
        threshold_time = time.time() - (lookback_hours * 3600)
        
        processed_count = 0
        
        for report_type in report_types:
            # Find all report files of this type
            pattern = os.path.join(data_dir, f"{report_type}_info_*.json")
            report_files = glob.glob(pattern)
            
            for report_file in report_files:
                # Check if file is recent enough
                if os.path.getmtime(report_file) < threshold_time:
                    continue
                
                try:
                    with open(report_file, 'r') as f:
                        report_data = json.load(f)
                    
                    # Format and send to Loki
                    log_entry = self.format_log_entry(report_data)
                    
                    if self.send_batch(log_entry["streams"]):
                        processed_count += 1
                        self.logger.info(f"Sent {report_file} to Loki")
                    else:
                        self.logger.error(f"Failed to send {report_file} to Loki")
                        
                except (json.JSONDecodeError, KeyError) as e:
                    self.logger.error(f"Error processing {report_file}: {e}")
                    continue
        
        self.logger.info(f"Processed {processed_count} report files")
        return processed_count
    
    def tail_reports(self, data_dir="/home/cbwinslow/reports/data", 
                    report_types=None, interval=30):
        """
        Continuously monitor for new reports and send them to Loki
        """
        if report_types is None:
            report_types = ["system", "network", "filesystem", "error", "log", "container"]
        
        # Keep track of files already processed
        processed_files = set()
        
        while True:
            try:
                for report_type in report_types:
                    pattern = os.path.join(data_dir, f"{report_type}_info_*.json")
                    report_files = glob.glob(pattern)
                    
                    for report_file in report_files:
                        if report_file in processed_files:
                            continue
                        
                        # Check if file is fully written (not being written to now)
                        file_time = os.path.getmtime(report_file)
                        if time.time() - file_time < 5:  # Wait 5 seconds to ensure file is fully written
                            continue
                        
                        try:
                            with open(report_file, 'r') as f:
                                report_data = json.load(f)
                            
                            # Format and send to Loki
                            log_entry = self.format_log_entry(report_data)
                            
                            if self.send_batch(log_entry["streams"]):
                                processed_files.add(report_file)
                                self.logger.info(f"Sent new {report_file} to Loki")
                            else:
                                self.logger.error(f"Failed to send {report_file} to Loki")
                                
                        except (json.JSONDecodeError, KeyError) as e:
                            self.logger.error(f"Error processing {report_file}: {e}")
                            continue
                
                # Wait before next check
                time.sleep(interval)
                
            except KeyboardInterrupt:
                self.logger.info("Loki integration stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Error in tail_reports: {e}")
                time.sleep(interval)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Loki Integration for Enterprise Reporting System')
    parser.add_argument('--loki-url', type=str, default='http://localhost:3100',
                        help='Loki server URL (default: http://localhost:3100)')
    parser.add_argument('--username', type=str, help='Username for Loki authentication')
    parser.add_argument('--password', type=str, help='Password for Loki authentication')
    parser.add_argument('--api-key', type=str, help='API Key or Bearer token for Loki authentication')
    parser.add_argument('--label', action='append', default=[],
                        help='Labels in key=value format (can be used multiple times)')
    parser.add_argument('--batch-size', type=int, default=100, help='Batch size for sending logs (default: 100)')
    parser.add_argument('--batch-wait', type=str, default='5s', help='Wait time for batching (default: 5s)')
    parser.add_argument('--data-dir', type=str, default='/home/cbwinslow/reports/data',
                        help='Directory containing report files (default: /home/cbwinslow/reports/data)')
    parser.add_argument('--tail', action='store_true', help='Run in tail mode to continuously monitor for new reports')
    parser.add_argument('--process-all', action='store_true', help='Process all existing reports and exit')
    parser.add_argument('--interval', type=int, default=30, help='Interval for checking new reports (in seconds)')
    
    args = parser.parse_args()
    
    # Parse labels
    labels = {"job": "reports", "source": "enterprise-reporting"}
    for label_str in args.label:
        if '=' in label_str:
            key, value = label_str.split('=', 1)
            labels[key] = value
    
    # Initialize Loki integration
    loki = LokiIntegration(
        loki_url=args.loki_url,
        username=args.username,
        password=args.password,
        api_key=args.api_key,
        labels=labels,
        batch_size=args.batch_size,
        batch_wait=args.batch_wait
    )
    
    if args.process_all:
        # Process all existing reports and exit
        loki.process_report_files(args.data_dir)
    elif args.tail:
        # Run in continuous mode
        loki.tail_reports(args.data_dir, interval=args.interval)
    else:
        # Process recent reports and exit
        loki.process_report_files(args.data_dir)

if __name__ == "__main__":
    main()