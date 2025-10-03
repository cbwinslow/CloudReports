#!/usr/bin/env python3

# Elasticsearch Integration for Enterprise Reporting System
# Indexes collected reports into Elasticsearch for advanced search and analysis

import os
import json
import logging
from datetime import datetime
import glob
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import argparse
import time

class ElasticsearchIntegration:
    """
    Elasticsearch integration for the Enterprise Reporting System
    """
    
    def __init__(self, es_hosts=None, username=None, password=None, 
                 api_key=None, use_ssl=True, verify_certs=True, 
                 index_pattern="reports-%Y.%m.%d"):
        self.index_pattern = index_pattern
        self.logger = logging.getLogger(__name__)
        
        # Set up Elasticsearch client
        es_args = {
            'hosts': es_hosts or ['localhost:9200'],
            'use_ssl': use_ssl,
            'verify_certs': verify_certs,
            'timeout': 30
        }
        
        if username and password:
            es_args['http_auth'] = (username, password)
        elif api_key:
            es_args['api_key'] = api_key
            
        self.es = Elasticsearch(**es_args)
        
        # Test connection
        if not self.es.ping():
            raise ValueError("Cannot connect to Elasticsearch")
        
        self.logger.info("Successfully connected to Elasticsearch")
    
    def create_index_template(self):
        """
        Create an index template for reports
        """
        template = {
            "index_patterns": [self.index_pattern.replace('%Y.%m.%d', '*')],
            "template": {
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "hostname": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "data": {"type": "object", "enabled": True}
                    }
                }
            }
        }
        
        try:
            self.es.indices.put_template(name="reports", body=template)
            self.logger.info("Index template created successfully")
        except Exception as e:
            self.logger.error(f"Error creating index template: {e}")
    
    def prepare_document(self, report_file):
        """
        Prepare a report file for indexing in Elasticsearch
        """
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing JSON in {report_file}: {e}")
            return None
        
        # Determine the index name based on timestamp
        timestamp = report_data.get('timestamp', datetime.utcnow().isoformat())
        index_date = datetime.fromisoformat(timestamp.replace('Z', '').split('.')[0])
        index_name = index_date.strftime(self.index_pattern)
        
        # Create document
        doc = {
            '_index': index_name,
            '_source': report_data
        }
        
        return doc
    
    def index_reports(self, data_dir="/home/cbwinslow/reports/data", 
                     report_types=None, lookback_hours=24):
        """
        Index report files into Elasticsearch
        """
        if report_types is None:
            report_types = ["system", "network", "filesystem", "error", "log", "container"]
        
        # Calculate time threshold
        threshold_time = time.time() - (lookback_hours * 3600)
        documents = []
        
        for report_type in report_types:
            # Find all report files of this type
            pattern = os.path.join(data_dir, f"{report_type}_info_*.json")
            report_files = glob.glob(pattern)
            
            for report_file in report_files:
                # Check if file is recent enough
                if os.path.getmtime(report_file) < threshold_time:
                    continue
                
                doc = self.prepare_document(report_file)
                if doc:
                    documents.append(doc)
        
        if documents:
            try:
                # Bulk index the documents
                success_count, failed_docs = bulk(
                    self.es,
                    documents,
                    max_retries=3,
                    chunk_size=500
                )
                
                self.logger.info(f"Successfully indexed {success_count} documents")
                
                if failed_docs:
                    self.logger.warning(f"Failed to index {len(failed_docs)} documents")
                    for doc in failed_docs:
                        self.logger.error(f"Failed to index document: {doc}")
                        
            except Exception as e:
                self.logger.error(f"Error bulk indexing documents: {e}")
        else:
            self.logger.info("No documents to index")
    
    def search(self, query, size=10, index_pattern=None):
        """
        Search for reports in Elasticsearch
        """
        if index_pattern is None:
            index_pattern = self.index_pattern.replace('%Y.%m.%d', '*')
        
        search_body = {
            "query": query,
            "size": size,
            "sort": [{"timestamp": {"order": "desc"}}]
        }
        
        try:
            result = self.es.search(index=index_pattern, body=search_body)
            return result
        except Exception as e:
            self.logger.error(f"Error searching Elasticsearch: {e}")
            return None
    
    def get_report_types(self, index_pattern=None):
        """
        Get distinct report types from Elasticsearch
        """
        if index_pattern is None:
            index_pattern = self.index_pattern.replace('%Y.%m.%d', '*')
        
        aggregation_body = {
            "size": 0,
            "aggs": {
                "report_types": {
                    "terms": {"field": "type.keyword"}
                }
            }
        }
        
        try:
            result = self.es.search(index=index_pattern, body=aggregation_body)
            buckets = result['aggregations']['report_types']['buckets']
            return [bucket['key'] for bucket in buckets]
        except Exception as e:
            self.logger.error(f"Error getting report types: {e}")
            return []

def main():
    parser = argparse.ArgumentParser(description='Elasticsearch Integration for Enterprise Reporting System')
    parser.add_argument('--es-hosts', nargs='+', default=['localhost:9200'],
                        help='Elasticsearch hosts (default: localhost:9200)')
    parser.add_argument('--es-username', type=str, help='Elasticsearch username')
    parser.add_argument('--es-password', type=str, help='Elasticsearch password')
    parser.add_argument('--es-api-key', type=str, help='Elasticsearch API key')
    parser.add_argument('--index-pattern', type=str, default='reports-%Y.%m.%d',
                        help='Index pattern for reports (default: reports-%%Y.%%m.%%d)')
    parser.add_argument('--data-dir', type=str, default='/home/cbwinslow/reports/data',
                        help='Directory containing report files (default: /home/cbwinslow/reports/data)')
    parser.add_argument('--lookback-hours', type=int, default=24,
                        help='Lookback time in hours for processing reports (default: 24)')
    parser.add_argument('--create-template', action='store_true',
                        help='Create index template in Elasticsearch')
    parser.add_argument('--index-reports', action='store_true',
                        help='Index reports into Elasticsearch')
    parser.add_argument('--ssl', action='store_true', default=True,
                        help='Use SSL connection to Elasticsearch (default: True)')
    parser.add_argument('--no-verify-certs', action='store_true', default=False,
                        help='Skip certificate verification (default: False)')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Initialize Elasticsearch integration
        es_integration = ElasticsearchIntegration(
            es_hosts=args.es_hosts,
            username=args.es_username,
            password=args.es_password,
            api_key=args.es_api_key,
            use_ssl=args.ssl,
            verify_certs=not args.no_verify_certs,
            index_pattern=args.index_pattern
        )
        
        if args.create_template:
            es_integration.create_index_template()
        
        if args.index_reports:
            es_integration.index_reports(
                data_dir=args.data_dir,
                lookback_hours=args.lookback_hours
            )
            
    except Exception as e:
        logging.error(f"Elasticsearch integration error: {e}")
        exit(1)

if __name__ == "__main__":
    main()