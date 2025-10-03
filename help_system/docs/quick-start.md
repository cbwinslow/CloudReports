# Quick Start Guide

## Overview
This guide will help you get the Enterprise Reporting System up and running quickly with basic functionality.

## Prerequisites
- Python 3.8 or higher
- Git
- SSH access (for remote collection)
- System with at least 2GB RAM and 5GB disk space

## Installation Methods

### Option 1: Using pip (Recommended)
```bash
# Install the package
pip install enterprise-reporting-system

# Initialize the system
reports-init

# Start the services
reports-start
```

### Option 2: Using Docker
```bash
# Pull the latest image
docker pull enterprisereporting/system:latest

# Run the container
docker run -d -p 8080:8080 -v reports-data:/app/data enterprisereporting/system:latest
```

### Option 3: From Source
```bash
# Clone the repository
git clone https://github.com/your-org/enterprise-reporting.git
cd enterprise-reporting

# Install dependencies
pip install -r requirements.txt

# Initialize the system
python -m reports.init
```

## Basic Configuration

### Configuration File Location
The main configuration file is located at `~/.reports/config.json`

### Minimal Configuration
```json
{
  "general": {
    "output_dir": "/home/user/reports/data",
    "retention_days": 30,
    "compression": true
  },
  "report_types": {
    "system": {
      "enabled": true,
      "schedule": "hourly"
    },
    "network": {
      "enabled": true,
      "schedule": "hourly"
    }
  }
}
```

## First Run

### 1. Run a Test Collection
```bash
# Run all enabled reports once
./run_reports.sh full

# Run specific report type
./run_reports.sh system
```

### 2. Verify Reports Were Created
```bash
# Check the reports directory
ls -la ~/reports/data/

# View the most recent system report
cat ~/reports/data/system_info_*.json | jq '.'
```

### 3. Start the Web Interface
```bash
# Start the web server in background
python web_server.py --host 0.0.0.0 --port 8081 &

# Access the dashboard at http://localhost:8081
```

## Working Examples

### Example 1: Configure Remote Server Collection
```bash
# Edit the configuration
nano ~/.reports/config.json

# Add a remote server:
{
  "remote_servers": {
    "enabled": true,
    "servers": [
      {
        "name": "web-server-1",
        "host": "192.168.1.100",
        "port": 22,
        "user": "reports",
        "ssh_key": "/home/user/.ssh/reports_key"
      }
    ]
  }
}

# Test SSH connection
ssh -i /home/user/.ssh/reports_key reports@192.168.1.100

# Run remote collection
./run_reports.sh remote
```

### Example 2: Configure Prometheus Integration
```bash
# Update configuration
{
  "integrations": {
    "prometheus": {
      "enabled": true,
      "exporter_port": 9090,
      "metrics_path": "/metrics"
    }
  }
}

# Start the Prometheus exporter
python integrations/prometheus_exporter.py --port 9090

# Verify metrics are available
curl http://localhost:9090/metrics
```

### Example 3: Set Up Alerting
```bash
# Configure alerts in config.json
{
  "alerting": {
    "providers": {
      "email": {
        "enabled": true,
        "smtp_server": "smtp.company.com",
        "from": "reports@company.com",
        "recipients": ["admin@company.com"]
      }
    },
    "rules": [
      {
        "name": "high_cpu_usage",
        "condition": "system.cpu.usage > 80",
        "frequency": "5m",
        "severity": "warning"
      }
    ]
  }
}

# Start the alerting system
python alerting_system.py
```

## Verification Steps

### 1. Check System Status
```bash
# Check if API is running
curl http://localhost:8080/api/v1/health

# Check collected reports
./run_reports.sh list
```

### 2. Verify Data Collection
```bash
# Look for recent report files
find ~/reports/data -name "*.json" -mtime -1

# Check report contents
head -20 ~/reports/data/system_info_*.json
```

### 3. Test Web Interface
- Open your browser to `http://localhost:8081`
- Verify dashboard loads and shows system information
- Check that reports appear in the interface

## Troubleshooting Quick Fixes

### Issue: Permission denied errors
```bash
# Set proper permissions
chmod +x *.sh
chmod 600 ~/.reports/config.json
```

### Issue: SSH connection failures
```bash
# Verify SSH key permissions
chmod 600 ~/.ssh/reports_key
chmod 644 ~/.ssh/reports_key.pub

# Test SSH connection manually
ssh -i ~/.ssh/reports_key -o ConnectTimeout=10 username@hostname
```

### Issue: API not responding
```bash
# Check if API service is running
ps aux | grep api_server

# Start API server manually
python api_server.py --port 8080
```

## Next Steps

After successful quick start:

1. **Configure additional report types** based on your needs
2. **Set up monitoring integrations** for your existing systems
3. **Configure alerts** for important metrics
4. **Review security settings** for production use
5. **Set up automated scheduling** for regular report collection

## Support Resources

- [Full Documentation](index.md)
- [Troubleshooting Guide](troubleshooting.md)
- [API Reference](api-reference.md)
- [Community Support](support.md)