#!/usr/bin/env python3
"""
OpenSearch Integration Module
Provides integration with OpenSearch for log aggregation and search
"""

import json
import datetime
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import defaultdict
import time
import threading


@dataclass
class OpenSearchIndex:
    """Data structure for OpenSearch index"""
    name: str
    docs_count: int
    store_size: str
    creation_date: datetime.datetime


@dataclass
class OpenSearchDocument:
    """Data structure for OpenSearch document"""
    id: str
    index: str
    source: Dict
    timestamp: datetime.datetime


class OpenSearchClient:
    """Client for interacting with OpenSearch API"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.host = config.get('opensearch_host', 'localhost')
        self.port = config.get('opensearch_port', 9200)
        self.username = config.get('opensearch_username', 'admin')
        self.password = config.get('opensearch_password', 'admin')
        self.use_ssl = config.get('opensearch_use_ssl', False)
        
        # For demonstration purposes, we'll use direct HTTP requests
        # In a real implementation, you would use the opensearch-py library
        protocol = 'https' if self.use_ssl else 'http'
        self.base_url = f"{protocol}://{self.host}:{self.port}"
        self.auth = (self.username, self.password) if self.username and self.password else None
    
    def test_connection(self) -> bool:
        """Test connection to OpenSearch instance"""
        try:
            response = requests.get(
                f"{self.base_url}/_cluster/health",
                auth=self.auth,
                verify=not self.use_ssl,  # Skip SSL verification for demo
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def get_cluster_info(self) -> Optional[Dict]:
        """Get cluster information"""
        try:
            response = requests.get(
                f"{self.base_url}",
                auth=self.auth,
                verify=not self.use_ssl,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None
    
    def get_indices(self) -> List[OpenSearchIndex]:
        """Get list of all indices"""
        indices = []
        try:
            response = requests.get(
                f"{self.base_url}/_cat/indices?format=json",
                auth=self.auth,
                verify=not self.use_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                response_data = response.json()
                for index_info in response_data:
                    # Parse creation date - in reality this would come from index settings
                    creation_date = datetime.datetime.now()
                    
                    index = OpenSearchIndex(
                        name=index_info.get('index', ''),
                        docs_count=int(index_info.get('docs.count', 0)) if index_info.get('docs.count', '0') != '-' else 0,
                        store_size=index_info.get('store.size', '0'),
                        creation_date=creation_date
                    )
                    indices.append(index)
        except Exception as e:
            print(f"Error getting indices: {e}")
        
        return indices
    
    def create_index(self, index_name: str, mappings: Dict = None) -> bool:
        """Create a new index"""
        try:
            url = f"{self.base_url}/{index_name}"
            payload = {}
            if mappings:
                payload = {"mappings": mappings}
            
            response = requests.put(
                url,
                auth=self.auth,
                json=payload,
                verify=not self.use_ssl,
                timeout=30
            )
            return response.status_code in [200, 201]
        except Exception as e:
            print(f"Error creating index: {e}")
            return False
    
    def index_document(self, index_name: str, document: Dict, doc_id: str = None) -> bool:
        """Index a document"""
        try:
            if doc_id:
                url = f"{self.base_url}/{index_name}/_doc/{doc_id}"
            else:
                url = f"{self.base_url}/{index_name}/_doc/"
            
            response = requests.post(
                url,
                auth=self.auth,
                json=document,
                verify=not self.use_ssl,
                timeout=30
            )
            return response.status_code in [200, 201]
        except Exception as e:
            print(f"Error indexing document: {e}")
            return False
    
    def search_documents(self, index_name: str, query: Dict) -> List[OpenSearchDocument]:
        """Search for documents"""
        documents = []
        try:
            url = f"{self.base_url}/{index_name}/_search"
            response = requests.post(
                url,
                auth=self.auth,
                json=query,
                verify=not self.use_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                response_data = response.json()
                hits = response_data.get('hits', {}).get('hits', [])
                
                for hit in hits:
                    doc = OpenSearchDocument(
                        id=hit.get('_id', ''),
                        index=hit.get('_index', ''),
                        source=hit.get('_source', {}),
                        timestamp=datetime.datetime.now()  # In real implementation, extract from source
                    )
                    documents.append(doc)
        except Exception as e:
            print(f"Error searching documents: {e}")
        
        return documents


class OpenSearchIntegration:
    """Integrates system monitoring data with OpenSearch for search and analysis"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.client = OpenSearchClient(config)
        self.monitoring = False
        self.monitor_thread = None
        self.index_mappings = {
            "properties": {
                "timestamp": {"type": "date"},
                "report_type": {"type": "keyword"},
                "hostname": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "message": {"type": "text"},
                "data": {"type": "object", "enabled": False}
            }
        }
    
    def initialize_indices(self) -> bool:
        """Initialize standard indices for reporting system"""
        if not self.client.test_connection():
            print("Failed to connect to OpenSearch")
            return False
        
        # Define index names
        index_names = [
            "reports-system-metrics",
            "reports-security-events", 
            "reports-network-traffic",
            "reports-process-data",
            "reports-storage-data"
        ]
        
        success = True
        for index_name in index_names:
            if not self.client.create_index(index_name, self.index_mappings):
                print(f"Failed to create index: {index_name}")
                success = False
        
        if success:
            print("Standard indices created successfully")
        
        return success
    
    def index_report_data(self, report_type: str, data: Dict) -> bool:
        """Index report data in OpenSearch"""
        if not self.client.test_connection():
            return False
        
        # Create document structure
        document = {
            "timestamp": datetime.datetime.now().isoformat(),
            "report_type": report_type,
            "hostname": data.get('hostname', 'unknown'),
            "severity": data.get('severity', 'info'),
            "message": f"System {report_type} report generated",
            "data": data
        }
        
        # Choose appropriate index based on report type
        index_name = "reports-system-metrics"  # Default
        if "security" in report_type.lower():
            index_name = "reports-security-events"
        elif "network" in report_type.lower():
            index_name = "reports-network-traffic"
        elif "process" in report_type.lower():
            index_name = "reports-process-data"
        elif "storage" in report_type.lower():
            index_name = "reports-storage-data"
        
        return self.client.index_document(index_name, document)
    
    def search_reports(self, query: str, report_type: str = None) -> List[OpenSearchDocument]:
        """Search for reports in OpenSearch"""
        # Build query
        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": query,
                                "fields": ["message", "data.*"]
                            }
                        }
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 100
        }
        
        if report_type:
            es_query["query"]["bool"]["must"].append({
                "term": {"report_type": report_type}
            })
        
        # Use appropriate index based on search parameters
        index_name = "reports-system-metrics"
        if report_type and "security" in report_type.lower():
            index_name = "reports-security-events"
        elif report_type and "network" in report_type.lower():
            index_name = "reports-network-traffic"
        elif report_type and "process" in report_type.lower():
            index_name = "reports-process-data"
        elif report_type and "storage" in report_type.lower():
            index_name = "reports-storage-data"
        else:
            # Search all report indices
            index_name = "reports-*"
        
        return self.client.search_documents(index_name, es_query)
    
    def start_monitoring(self):
        """Start continuous monitoring and indexing with OpenSearch"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _monitor_loop(self):
        """Internal monitoring loop"""
        while self.monitoring:
            try:
                # In a real implementation, this would monitor for new reports
                # and index them in OpenSearch. For now, we'll just sleep.
                
                # Wait before next iteration
                time.sleep(self.config.get('sync_interval', 60))
                
            except Exception as e:
                print(f"Error in OpenSearch sync loop: {e}")
                time.sleep(self.config.get('sync_interval', 60))
    
    def generate_opensearch_integration_report(self) -> Dict:
        """Generate a report on OpenSearch integration status"""
        connection_ok = self.client.test_connection()
        
        report = {
            'report_type': 'OpenSearch Integration Report',
            'generated_at': datetime.datetime.now().isoformat(),
            'connection_status': 'connected' if connection_ok else 'disconnected',
            'opensearch_host': f"{self.config.get('opensearch_host', 'localhost')}:{self.config.get('opensearch_port', 9200)}",
            'configured': bool(self.config.get('opensearch_username'))
        }
        
        if connection_ok:
            cluster_info = self.client.get_cluster_info()
            indices = self.client.get_indices()
            
            report.update({
                'cluster_name': cluster_info.get("cluster_name") if cluster_info else "Unknown",
                'opensearch_version': cluster_info.get("version", {}).get("number") if cluster_info and "version" in cluster_info else "Unknown",
                'index_count': len(indices),
                'indices': [
                    {
                        'name': idx.name,
                        'docs_count': idx.docs_count,
                        'store_size': idx.store_size,
                        'creation_date': idx.creation_date.isoformat()
                    }
                    for idx in indices
                ]
            })
        
        return report


def run_opensearch_integration(config_path: Optional[str] = None) -> Dict:
    """
    Main function to run OpenSearch integration
    """
    # Default configuration
    config = {
        'opensearch_host': 'localhost',
        'opensearch_port': 9200,
        'opensearch_username': 'admin',
        'opensearch_password': 'admin',
        'opensearch_use_ssl': False,
        'sync_interval': 300,  # seconds
        'initialize_indices': True
    }
    
    if config_path:
        try:
            with open(config_path, 'r') as f:
                config.update(json.load(f))
        except FileNotFoundError:
            print(f"Config file {config_path} not found, using defaults")
    
    # Create an integration instance
    integration = OpenSearchIntegration(config)
    
    # Initialize indices if requested
    if config.get('initialize_indices', True):
        integration.initialize_indices()
    
    # Generate report
    report = integration.generate_opensearch_integration_report()
    
    # If continuous sync is requested, start monitoring
    if config.get('continuous_sync', False):
        integration.start_monitoring()
    
    return {
        'opensearch_integration_report': report
    }


if __name__ == "__main__":
    report = run_opensearch_integration()
    print(json.dumps(report, indent=2))