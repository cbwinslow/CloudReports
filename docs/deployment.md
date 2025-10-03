# Enterprise Deployment Guide

## Overview

This guide provides instructions for deploying the Enterprise Reporting System in production environments at scale. It covers single-server setups to large distributed deployments.

## Prerequisites

### System Requirements

- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+)
- **Minimum Resources**:
  - CPU: 2 cores
  - Memory: 4GB RAM
  - Storage: 50GB available space (adjust based on retention and collection frequency)
- **Network**: Outbound SSH access to monitored systems
- **Required Packages**: bash, coreutils, findutils, jq (recommended), systemd

### Network Requirements

- SSH access (TCP 22) to all target systems
- If using API: available port for HTTP/HTTPS communication
- If using integrations: access to monitoring systems (Prometheus, etc.)

## Single Server Deployment

### Quick Installation

1. Clone or download the system:
   ```bash
   git clone https://github.com/your-org/enterprise-reporting.git ~/reports
   # Or download and extract the archive
   ```

2. Set up the directory structure:
   ```bash
   cd ~/reports
   chmod +x *.sh */*.sh */*/*.sh
   ```

3. Configure the system:
   ```bash
   cp config.example.json config.json
   # Edit config.json with appropriate settings
   vim config.json
   ```

4. Run initial tests:
   ```bash
   ./run_reports.sh system
   ```

### Configuration for Production

1. Set up proper user account:
   ```bash
   sudo useradd -r -s /bin/bash -d /home/reports reports
   sudo chown -R reports:reports ~/reports/
   ```

2. Create secure directories:
   ```bash
   sudo mkdir -p /var/lib/reports /var/log/reports
   sudo chown reports:reports /var/lib/reports /var/log/reports
   ```

3. Configure data retention:
   ```bash
   # Update config.json to point to secure directories
   # Set appropriate retention policies
   ```

## Distributed Deployment

### Architecture Overview

For large-scale deployments, consider this architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Central       │    │   Data           │    │   Monitoring    │
│   Collector     │    │   Storage        │    │   Interface     │
│                 │    │                  │    │                 │
│  (N Servers)    │◄──►│ (Scalable        │◄──►│  (Grafana, etc.)│
│                 │    │  Storage)        │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Multiple Collection Nodes

1. Set up a primary collection server with a shared file system or database backend

2. Deploy collection agents on multiple servers:
   ```bash
   # On each collection node
   git clone https://github.com/your-org/enterprise-reporting.git ~/reports
   # Configure to use shared storage backend
   vim ~/reports/config.json
   ```

3. Configure load balancing if needed:
   ```bash
   # Example using cron to distribute collection load
   # */30 * * * * /home/reports/run_reports.sh system  # Node 1
   # 15,45 * * * * /home/reports/run_reports.sh system  # Node 2
   ```

### High Availability

1. Set up multiple collection servers in active-passive or active-active configuration

2. Use shared storage with appropriate locking mechanisms

3. Implement health checks and automatic failover

## Integration Deployment

### With Existing Monitoring Stack

#### Prometheus Integration

1. Configure Prometheus exporter:
   ```bash
   # Enable Prometheus integration in config.json
   {
     "integrations": {
       "prometheus": {
         "enabled": true,
         "exporter_port": 9090
       }
     }
   }
   ```

2. Add to Prometheus configuration:
   ```yaml
   scrape_configs:
     - job_name: 'reports'
       static_configs:
         - targets: ['reporting-server:9090']
   ```

#### Grafana Integration

1. Import provided dashboards from `~/reports/grafana_dashboards/`

2. Configure data sources to point to your Prometheus/Loki endpoints

### With Security Tools

#### SIEM Integration

1. Configure log forwarding to your SIEM:
   ```json
   {
     "integrations": {
       "syslog": {
         "enabled": true,
         "server": "siem.example.com",
         "port": 514
       }
     }
   }
   ```

## Containerized Deployment

### Docker Configuration

Create a Dockerfile for containerized deployment:

```dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    bash \
    coreutils \
    jq \
    openssh-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .

RUN chmod +x *.sh */*.sh */*/*.sh

USER 1000

CMD ["./run_reports.sh", "full"]
```

### Kubernetes Deployment

For Kubernetes environments:

1. Create a ConfigMap for configuration:
   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: reporting-config
   data:
     config.json: |
       {
         "general": {
           "output_dir": "/data/reports"
         }
       }
   ```

2. Deploy as a CronJob for scheduled reports:
   ```yaml
   apiVersion: batch/v1
   kind: CronJob
   metadata:
     name: enterprise-reporting
   spec:
     schedule: "0 * * * *"
     jobTemplate:
       spec:
         template:
           spec:
             containers:
             - name: reporter
               image: your-registry/enterprise-reporting:latest
               command: ["./run_reports.sh", "full"]
               volumeMounts:
               - name: config
                 mountPath: /app/config.json
                 subPath: config.json
             volumes:
             - name: config
               configMap:
                 name: reporting-config
             restartPolicy: OnFailure
   ```

## Scaling Considerations

### Performance Optimization

1. Increase collection intervals for large environments
2. Distribute collection across multiple nodes
3. Use faster storage for data output (SSDs)
4. Optimize network connectivity to reduce collection time

### Resource Management

1. Monitor resource usage:
   - CPU during collection periods
   - Memory usage with large datasets
   - Disk I/O for data storage
   - Network bandwidth for remote collection

2. Implement resource limits to prevent system degradation

### Data Management

1. Regular cleanup of old reports
2. Data compression to reduce storage requirements
3. Archival of historical data to long-term storage

## Security Deployment

### Network Segmentation

Deploy in a secure network segment with limited access to target systems.

### Certificate Management

If using API endpoints, implement proper certificate management:
- Use internal certificate authority
- Implement certificate auto-renewal
- Regular certificate rotation

## Troubleshooting Common Issues

### Collection Failures

1. Verify SSH connectivity to target systems
2. Check SSH key permissions and configuration
3. Review target system SSH settings

### Performance Issues

1. Check system resource utilization during collection
2. Verify network connectivity and bandwidth
3. Review script execution times and optimize if needed

## Maintenance

### Regular Tasks

1. Monitor disk space on collection servers
2. Review collected reports for anomalies
3. Update system and dependencies regularly
4. Rotate SSH keys periodically

### Backups

1. Back up configuration files regularly
2. Preserve historical reports as needed for compliance
3. Test backup restoration procedures