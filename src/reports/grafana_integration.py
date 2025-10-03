#!/usr/bin/env python3
"""
Grafana Integration Module
Provides integration with Grafana for dashboard visualization and alerting
"""

import json
import datetime
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass
import time
import threading
import subprocess


@dataclass
class GrafanaDashboard:
    """Data structure for Grafana dashboard"""
    dashboard_id: str
    title: str
    uid: str
    url: str
    created: datetime.datetime
    updated: datetime.datetime
    tags: List[str]
    timezone: str


@dataclass
class GrafanaPanel:
    """Data structure for Grafana panel"""
    panel_id: int
    title: str
    type: str
    datasource: str
    targets: List[Dict]
    grid_pos: Dict


@dataclass
class GrafanaAnnotation:
    """Data structure for Grafana annotation"""
    id: int
    text: str
    time: datetime.datetime
    tags: List[str]


class GrafanaClient:
    """Client for interacting with Grafana API"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.grafana_url = config.get('grafana_url', 'http://localhost:3000')
        self.api_key = config.get('grafana_api_key', '')
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
    def test_connection(self) -> bool:
        """Test connection to Grafana instance"""
        try:
            response = requests.get(
                f"{self.grafana_url}/api/health",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def get_org_info(self) -> Optional[Dict]:
        """Get organization information"""
        try:
            response = requests.get(
                f"{self.grafana_url}/api/org",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
        except Exception:
            pass
        return None
    
    def create_dashboard(self, title: str, panels: List[GrafanaPanel]) -> Optional[Dict]:
        """Create a new dashboard in Grafana"""
        dashboard_data = {
            "dashboard": {
                "title": title,
                "panels": [
                    {
                        "id": panel.panel_id,
                        "title": panel.title,
                        "type": panel.type,
                        "datasource": panel.datasource,
                        "targets": panel.targets,
                        "gridPos": panel.grid_pos
                    }
                    for panel in panels
                ],
                "time": {
                    "from": "now-6h",
                    "to": "now"
                },
                "timezone": "browser"
            },
            "folderId": 0,
            "overwrite": True
        }
        
        try:
            response = requests.post(
                f"{self.grafana_url}/api/dashboards/db",
                headers=self.headers,
                json=dashboard_data,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error creating dashboard: {e}")
        
        return None
    
    def get_dashboards(self) -> List[GrafanaDashboard]:
        """Get list of all dashboards"""
        dashboards = []
        try:
            response = requests.get(
                f"{self.grafana_url}/api/search",
                headers=self.headers,
                params={"type": "dash-db"},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                for item in data:
                    dashboard = GrafanaDashboard(
                        dashboard_id=item.get('id', ''),
                        title=item.get('title', ''),
                        uid=item.get('uid', ''),
                        url=item.get('url', ''),
                        created=datetime.datetime.fromisoformat(item.get('created', datetime.datetime.now().isoformat()).replace('Z', '+00:00')) if item.get('created') else datetime.datetime.now(),
                        updated=datetime.datetime.fromisoformat(item.get('updated', datetime.datetime.now().isoformat()).replace('Z', '+00:00')) if item.get('updated') else datetime.datetime.now(),
                        tags=item.get('tags', []),
                        timezone=item.get('timezone', 'browser')
                    )
                    dashboards.append(dashboard)
        except Exception as e:
            print(f"Error getting dashboards: {e}")
        
        return dashboards
    
    def create_annotation(self, text: str, tags: List[str] = None) -> bool:
        """Create an annotation in Grafana"""
        if tags is None:
            tags = ["system-alert"]
        
        annotation_data = {
            "time": int(time.time() * 1000),  # Grafana uses milliseconds
            "text": text,
            "tags": tags
        }
        
        try:
            response = requests.post(
                f"{self.grafana_url}/api/annotations",
                headers=self.headers,
                json=annotation_data,
                timeout=10
            )
            
            return response.status_code == 200
        except Exception as e:
            print(f"Error creating annotation: {e}")
            return False


class GrafanaIntegration:
    """Integrates system monitoring data with Grafana dashboards"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.client = GrafanaClient(config)
        self.monitoring = False
        self.monitor_thread = None
        
    def initialize_dashboards(self) -> bool:
        """Initialize standard dashboards for system monitoring"""
        # Test connection first
        if not self.client.test_connection():
            print("Failed to connect to Grafana")
            return False
        
        # Create system performance dashboard
        system_panels = [
            GrafanaPanel(
                panel_id=1,
                title="CPU Usage",
                type="graph",
                datasource="Prometheus",
                targets=[{"expr": "100 - (avg by (instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)"}],
                grid_pos={"h": 8, "w": 12, "x": 0, "y": 0}
            ),
            GrafanaPanel(
                panel_id=2,
                title="Memory Usage",
                type="graph",
                datasource="Prometheus", 
                targets=[{"expr": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100"}],
                grid_pos={"h": 8, "w": 12, "x": 12, "y": 0}
            )
        ]
        
        # Create network dashboard
        network_panels = [
            GrafanaPanel(
                panel_id=1,
                title="Network Traffic",
                type="graph",
                datasource="Prometheus",
                targets=[{"expr": "irate(node_network_receive_bytes_total[5m])"}],
                grid_pos={"h": 8, "w": 12, "x": 0, "y": 0}
            )
        ]
        
        # Create storage dashboard
        storage_panels = [
            GrafanaPanel(
                panel_id=1,
                title="Disk Usage",
                type="graph",
                datasource="Prometheus",
                targets=[{"expr": "100 - ((node_filesystem_avail_bytes * 100) / node_filesystem_size_bytes)"}],
                grid_pos={"h": 8, "w": 12, "x": 0, "y": 0}
            )
        ]
        
        # Create dashboards
        self.client.create_dashboard("System Performance", system_panels)
        self.client.create_dashboard("Network Monitoring", network_panels)
        self.client.create_dashboard("Storage Monitoring", storage_panels)
        
        print("Standard dashboards created successfully")
        return True
    
    def sync_system_data(self) -> Dict:
        """Sync system monitoring data with Grafana"""
        if not self.client.test_connection():
            return {"success": False, "error": "Cannot connect to Grafana"}
        
        # In a real implementation, this would pull data from your monitoring system
        # and push it to Grafana. For demonstration, we'll just return a status.
        
        try:
            org_info = self.client.get_org_info()
            dashboards = self.client.get_dashboards()
            
            return {
                "success": True,
                "organization": org_info.get("name") if org_info else "Unknown",
                "dashboard_count": len(dashboards),
                "synced_at": datetime.datetime.now().isoformat()
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def send_alert(self, title: str, message: str, severity: str = "info") -> bool:
        """Send an alert to Grafana as an annotation"""
        tags = ["system-alert", f"severity-{severity}", "reports-system"]
        text = f"[{severity.upper()}] {title}: {message}"
        
        return self.client.create_annotation(text, tags)
    
    def start_monitoring(self):
        """Start continuous monitoring and sync with Grafana"""
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
                # Sync system data to Grafana
                result = self.sync_system_data()
                
                # Wait before next sync
                time.sleep(self.config.get('sync_interval', 60))
                
            except Exception as e:
                print(f"Error in Grafana sync loop: {e}")
                time.sleep(self.config.get('sync_interval', 60))
    
    def generate_grafana_integration_report(self) -> Dict:
        """Generate a report on Grafana integration status"""
        connection_ok = self.client.test_connection()
        
        report = {
            'report_type': 'Grafana Integration Report',
            'generated_at': datetime.datetime.now().isoformat(),
            'connection_status': 'connected' if connection_ok else 'disconnected',
            'grafana_url': self.config.get('grafana_url', 'not configured'),
            'configured': bool(self.config.get('grafana_api_key'))
        }
        
        if connection_ok:
            org_info = self.client.get_org_info()
            dashboards = self.client.get_dashboards()
            
            report.update({
                'organization': org_info.get("name") if org_info else "Unknown",
                'dashboard_count': len(dashboards),
                'dashboards': [
                    {
                        'title': db.title,
                        'uid': db.uid,
                        'url': db.url,
                        'updated': db.updated.isoformat()
                    }
                    for db in dashboards
                ]
            })
        
        return report


def run_grafana_integration(config_path: Optional[str] = None) -> Dict:
    """
    Main function to run Grafana integration
    """
    # Default configuration
    config = {
        'grafana_url': 'http://localhost:3000',
        'grafana_api_key': '',
        'sync_interval': 300,  # seconds
        'initialize_dashboards': True
    }
    
    if config_path:
        try:
            with open(config_path, 'r') as f:
                config.update(json.load(f))
        except FileNotFoundError:
            print(f"Config file {config_path} not found, using defaults")
    
    # Create an integration instance
    integration = GrafanaIntegration(config)
    
    # Initialize dashboards if requested
    if config.get('initialize_dashboards', True):
        integration.initialize_dashboards()
    
    # Generate report
    report = integration.generate_grafana_integration_report()
    
    # If continuous sync is requested, start monitoring
    if config.get('continuous_sync', False):
        integration.start_monitoring()
    
    return {
        'grafana_integration_report': report
    }


if __name__ == "__main__":
    report = run_grafana_integration()
    print(json.dumps(report, indent=2))