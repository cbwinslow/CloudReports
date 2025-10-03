#!/usr/bin/env python3

# Webhook Integration for Enterprise Reporting System
# Sends collected reports to external webhook endpoints

import os
import json
import time
import requests
import threading
import logging
import glob
from datetime import datetime
import hashlib
import hmac
from http.server import HTTPServer, BaseHTTPRequestHandler
import argparse

class WebhookIntegration:
    """
    Webhook integration for the Enterprise Reporting System
    """
    
    def __init__(self, webhook_urls, secret=None, headers=None, 
                 timeout=30, batch_size=10, retry_attempts=3):
        self.webhook_urls = webhook_urls if isinstance(webhook_urls, list) else [webhook_urls]
        self.secret = secret
        self.headers = headers or {}
        self.timeout = timeout
        self.batch_size = batch_size
        self.retry_attempts = retry_attempts
        self.session = requests.Session()
        
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def sign_payload(self, payload):
        """
        Sign the payload with the configured secret
        """
        if not self.secret:
            return None
        
        # Create signature using HMAC-SHA256
        signature = hmac.new(
            self.secret.encode('utf-8'),
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return f"sha256={signature}"
    
    def send_to_webhook(self, payload, url):
        """
        Send payload to a webhook URL with retry logic
        """
        if isinstance(payload, dict):
            payload = json.dumps(payload)
        
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'
        
        # Add signature if secret is configured
        if self.secret:
            signature = self.sign_payload(payload)
            if signature:
                headers['X-Signature'] = signature
        
        for attempt in range(self.retry_attempts):
            try:
                response = self.session.post(
                    url,
                    data=payload,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code in [200, 201, 202]:
                    self.logger.info(f"Successfully sent to {url} (Attempt {attempt + 1})")
                    return True
                else:
                    self.logger.warning(f"Webhook {url} returned {response.status_code}: {response.text} (Attempt {attempt + 1})")
                    
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Error sending to {url} (Attempt {attempt + 1}): {e}")
            
            if attempt < self.retry_attempts - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
        
        self.logger.error(f"Failed to send to {url} after {self.retry_attempts} attempts")
        return False
    
    def process_report_file(self, report_file):
        """
        Process a single report file and send its content to all webhooks
        """
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing JSON in {report_file}: {e}")
            return False
        
        # Add metadata to the report
        report_data['webhook_metadata'] = {
            'sent_at': datetime.utcnow().isoformat(),
            'report_file': os.path.basename(report_file),
            'processed_by': 'enterprise-reporting-webhook-integration'
        }
        
        success_count = 0
        total_count = len(self.webhook_urls)
        
        for url in self.webhook_urls:
            if self.send_to_webhook(report_data, url):
                success_count += 1
        
        if success_count == total_count:
            self.logger.info(f"All webhooks notified for {report_file}")
            return True
        else:
            self.logger.warning(f"Only {success_count}/{total_count} webhooks succeeded for {report_file}")
            return False
    
    def process_report_files(self, data_dir="/home/cbwinslow/reports/data",
                           report_types=None, lookback_hours=1):
        """
        Process multiple report files and send them to webhooks
        """
        if report_types is None:
            report_types = ["system", "network", "filesystem", "error", "log", "container"]
        
        # Calculate time threshold
        threshold_time = time.time() - (lookback_hours * 3600)
        processed_count = 0
        success_count = 0
        
        for report_type in report_types:
            # Find all report files of this type
            pattern = os.path.join(data_dir, f"{report_type}_info_*.json")
            report_files = glob.glob(pattern)
            
            for report_file in report_files:
                # Check if file is recent enough
                if os.path.getmtime(report_file) < threshold_time:
                    continue
                
                if self.process_report_file(report_file):
                    success_count += 1
                processed_count += 1
        
        self.logger.info(f"Processed {processed_count} files, successfully sent {success_count}")
        return success_count
    
    def tail_reports(self, data_dir="/home/cbwinslow/reports/data",
                    report_types=None, interval=30):
        """
        Continuously monitor for new reports and send them to webhooks
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
                        
                        if self.process_report_file(report_file):
                            processed_files.add(report_file)
                            self.logger.info(f"Sent new {report_file} to webhooks")
                        else:
                            self.logger.error(f"Failed to send {report_file} to webhooks")
                
                # Wait before next check
                time.sleep(interval)
                
            except KeyboardInterrupt:
                self.logger.info("Webhook integration stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Error in tail_reports: {e}")
                time.sleep(interval)

def main():
    parser = argparse.ArgumentParser(description='Webhook Integration for Enterprise Reporting System')
    parser.add_argument('--webhook-url', action='append', required=True,
                        help='Webhook URL to send reports to (can be used multiple times)')
    parser.add_argument('--secret', type=str, help='Secret for signing webhook payloads')
    parser.add_argument('--header', action='append', default=[],
                        help='Custom headers in key=value format (can be used multiple times)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='HTTP timeout in seconds (default: 30)')
    parser.add_argument('--batch-size', type=int, default=10,
                        help='Batch size for sending reports (default: 10)')
    parser.add_argument('--retry-attempts', type=int, default=3,
                        help='Number of retry attempts for failed requests (default: 3)')
    parser.add_argument('--data-dir', type=str, default='/home/cbwinslow/reports/data',
                        help='Directory containing report files (default: /home/cbwinslow/reports/data)')
    parser.add_argument('--lookback-hours', type=int, default=1,
                        help='Lookback time in hours for processing reports (default: 1)')
    parser.add_argument('--tail', action='store_true',
                        help='Run in tail mode to continuously monitor for new reports')
    parser.add_argument('--process-all', action='store_true',
                        help='Process all existing reports and exit')
    parser.add_argument('--interval', type=int, default=30,
                        help='Interval for checking new reports (default: 30)')
    
    args = parser.parse_args()
    
    # Parse custom headers
    headers = {}
    for header_str in args.header:
        if '=' in header_str:
            key, value = header_str.split('=', 1)
            headers[key] = value
    
    # Initialize webhook integration
    webhook_integration = WebhookIntegration(
        webhook_urls=args.webhook_url,
        secret=args.secret,
        headers=headers,
        timeout=args.timeout,
        batch_size=args.batch_size,
        retry_attempts=args.retry_attempts
    )
    
    if args.process_all:
        # Process all existing reports and exit
        webhook_integration.process_report_files(
            data_dir=args.data_dir,
            lookback_hours=10000  # Effectively all files
        )
    elif args.tail:
        # Run in continuous mode
        webhook_integration.tail_reports(
            data_dir=args.data_dir,
            interval=args.interval
        )
    else:
        # Process recent reports and exit
        webhook_integration.process_report_files(
            data_dir=args.data_dir,
            lookback_hours=args.lookback_hours
        )

if __name__ == "__main__":
    main()