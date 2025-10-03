# Integrations Guide

## Overview

The Enterprise Reporting System provides integrations with popular monitoring, logging, and visualization tools. This guide explains how to configure and use these integrations.

## Supported Integrations

### Prometheus

Prometheus integration allows the reporting system to expose metrics in a format that Prometheus can scrape.

#### Configuration

Enable Prometheus integration in `config.json`:

```json
{
  "integrations": {
    "prometheus": {
      "enabled": true,
      "exporter_port": 9090,
      "metrics_path": "/metrics",
      "namespace": "reports",
      "scrape_interval": "60s"
    }
  }
}
```

#### Setup

1. Install Python if not already available:
   ```bash
   sudo apt-get install python3 python3-pip
   ```

2. Install required Python packages:
   ```bash
   pip3 install prometheus-client
   ```

3. Run the Prometheus exporter:
   ```bash
   ./integrations/prometheus_exporter.py --port 9090
   ```

#### Metrics Format

The system exposes metrics in Prometheus text format:

```
# HELP reports_system_cpu_usage_percent Current CPU usage percentage
# TYPE reports_system_cpu_usage_percent gauge
reports_system_cpu_usage_percent{hostname="server1", report_type="system"} 15.2
```

### Grafana

Grafana integration provides visualization dashboards for the collected data.

#### Dashboard Import

1. Import the provided dashboards from `~/reports/grafana_dashboards/`
2. Configure data sources to point to your Prometheus instance
3. Customize dashboard variables and panels as needed

#### Dashboard Variables

The dashboards include variables for:

- Hostname selection
- Time range
- Report type filtering
- Metric-specific selectors

### Loki

Loki integration enables centralized log aggregation.

#### Configuration

Enable Loki integration in `config.json`:

```json
{
  "integrations": {
    "loki": {
      "enabled": true,
      "url": "http://loki:3100",
      "batch_size": 100,
      "batch_wait": "5s",
      "labels": {
        "job": "reports",
        "environment": "production"
      }
    }
  }
}
```

#### Log Format

The system sends logs to Loki in the following format:

```json
{
  "streams": [
    {
      "stream": {
        "job": "reports",
        "hostname": "server1",
        "report_type": "system"
      },
      "values": [
        ["1573257600000000000", "CPU usage: 15.2%"]
      ]
    }
  ]
}
```

### Elasticsearch/Kibana (ELK)

ELK integration enables indexing of reports for advanced search and analysis.

#### Configuration

Enable ELK integration in `config.json`:

```json
{
  "integrations": {
    "elasticsearch": {
      "enabled": true,
      "url": "http://elasticsearch:9200",
      "index_pattern": "reports-%Y.%m.%d",
      "username": "elastic",
      "password": "changeme",
      "api_key": null
    }
  }
}
```

### Graylog

Graylog integration provides centralized log management and analysis capabilities.

#### Configuration

Enable Graylog integration in `config.json`:

```json
{
  "integrations": {
    "graylog": {
      "enabled": true,
      "server": "graylog.example.com",
      "port": 12201,
      "protocol": "udp",
      "additional_fields": {
        "facility": "reports",
        "application": "enterprise-reporting"
      }
    }
  }
}
```

### Syslog

Syslog integration forwards events to a centralized syslog server.

#### Configuration

Enable Syslog integration in `config.json`:

```json
{
  "integrations": {
    "syslog": {
      "enabled": true,
      "server": "syslog.example.com",
      "port": 514,
      "protocol": "udp",
      "facility": "local0",
      "level": "info"
    }
  }
}
```

## Custom Integrations

### Webhook Integration

Send data to custom endpoints via webhooks:

```json
{
  "integrations": {
    "webhook": {
      "enabled": true,
      "url": "https://your-webhook-endpoint.com/api/reports",
      "method": "POST",
      "headers": {
        "Authorization": "Bearer your-token",
        "Content-Type": "application/json"
      },
      "timeout": "30s"
    }
  }
}
```

### Database Integration

Export data directly to databases (MySQL, PostgreSQL, etc.):

```json
{
  "integrations": {
    "database": {
      "enabled": true,
      "type": "postgresql",
      "host": "db.example.com",
      "port": 5432,
      "database": "reports",
      "username": "reports_user",
      "password": "secure_password",
      "table_prefix": "report_"
    }
  }
}
```

## Integration Scripts

### Prometheus Exporter

Create a Python script to expose metrics to Prometheus:

```python
#!/usr/bin/env python3

from prometheus_client import start_http_server, Gauge, Counter, Histogram
import time
import json
import os
import threading

class ReportsCollector:
    def __init__(self, data_dir="/home/cbwinslow/reports/data"):
        self.data_dir = data_dir
        self.metrics = {}
        
        # Define metrics
        self.cpu_usage = Gauge('reports_system_cpu_usage_percent', 'CPU usage percentage', ['hostname', 'report_type'])
        self.memory_usage = Gauge('reports_system_memory_usage_percent', 'Memory usage percentage', ['hostname', 'report_type'])
        self.disk_usage = Gauge('reports_filesystem_usage_percent', 'Disk usage percentage', ['hostname', 'mount_point', 'report_type'])
        self.process_count = Gauge('reports_process_count', 'Number of processes', ['hostname', 'report_type'])
        
    def collect(self):
        """Collect metrics from report files"""
        # Implementation would read JSON reports and update metrics
        pass

if __name__ == '__main__':
    collector = ReportsCollector()
    start_http_server(9090)
    print("Prometheus exporter started on port 9090")
    
    # In a real implementation, this would run continuously
    while True:
        time.sleep(15)
```

### API Integration

Create a REST API to provide programmatic access to reports:

```bash
#!/bin/bash

# Simple API to serve reports
serve_api() {
    local port="${1:-8080}"
    local data_dir="/home/cbwinslow/reports/data"
    
    # This would normally be implemented in a proper web framework
    # For demonstration, we'll outline the concept
    echo "Starting API server on port $port"
    # Implementation would include:
    # - HTTP server to handle requests
    # - Endpoints for different report types
    # - Authentication and authorization
    # - Data filtering and formatting
}
```

## Integration Best Practices

### Performance

1. Batch data when possible to reduce API calls
2. Implement caching for frequently accessed reports
3. Use appropriate collection intervals to avoid overwhelming systems

### Reliability

1. Implement retry mechanisms for failed transmissions
2. Use circuit breakers to prevent cascading failures
3. Monitor integration endpoints and alert on failures

### Security

1. Use encrypted connections (HTTPS/TLS) for all integrations
2. Implement proper authentication and authorization
3. Validate and sanitize data before transmission

### Error Handling

1. Implement comprehensive error handling for network issues
2. Log integration failures for troubleshooting
3. Provide fallback options when integrations are unavailable

## Troubleshooting Integrations

### Common Issues

1. **Connection timeouts**: Verify network connectivity and firewall rules
2. **Authentication failures**: Check credentials and permissions
3. **Data format errors**: Validate data before sending to integrations
4. **Rate limiting**: Implement appropriate delays and retry logic

### Logging

Enable detailed integration logging:

```json
{
  "logging": {
    "integrations": {
      "level": "debug",
      "file": "/var/log/reports_integrations.log"
    }
  }
}
```

## Monitoring Integration Health

### Health Checks

Implement health checks for each integration:

```bash
# Example health check endpoint
check_prometheus() {
    if curl -sf http://localhost:9090/metrics >/dev/null 2>&1; then
        echo "Prometheus exporter: OK"
        return 0
    else
        echo "Prometheus exporter: FAILED"
        return 1
    fi
}
```

### Alerting

Configure alerts for integration failures:

1. Monitor integration endpoints
2. Alert on failed data transmissions
3. Track data freshness and completeness