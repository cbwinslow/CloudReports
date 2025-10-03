# System Requirements

## Minimum Requirements

### Hardware Requirements
- **CPU**: 2 cores (4 cores recommended)
- **Memory**: 4GB RAM (8GB recommended)
- **Storage**: 10GB available space
  - Additional space required for report storage based on retention settings
  - Temporary space for processing (typically 1-2GB)
- **Network**: 100 Mbps connection (1 Gbps recommended for high-volume deployments)

### Software Requirements
- **Operating System**: 
  - Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+)
  - macOS 10.14+ (for development only)
  - Windows (WSL2) - limited support
- **Python**: 3.8 or higher
- **Required Packages**: 
  - bash, coreutils, findutils
  - openssh-client (for remote collection)
  - curl, wget (for integrations)

## Recommended Requirements

### For Small Deployments (< 100 systems)
- **CPU**: 4 cores
- **Memory**: 8GB RAM
- **Storage**: 50GB SSD (for reports with 30-day retention)
- **Network**: 1 Gbps connection

### For Medium Deployments (100-1000 systems)
- **CPU**: 8 cores
- **Memory**: 16GB RAM
- **Storage**: 500GB SSD (for reports with 30-day retention)
- **Network**: 1 Gbps connection
- **Database**: Dedicated PostgreSQL instance recommended

### For Large Deployments (> 1000 systems)
- **CPU**: 16+ cores
- **Memory**: 32GB+ RAM
- **Storage**: 2TB+ SSD with high IOPS
- **Network**: 10 Gbps connection
- **Database**: Dedicated high-performance database server
- **Load Balancer**: Hardware or cloud load balancer

## Python Version Compatibility

### Supported Versions
- ✅ **Python 3.8**: Full support
- ✅ **Python 3.9**: Full support
- ✅ **Python 3.10**: Full support
- ✅ **Python 3.11**: Full support
- ✅ **Python 3.12**: Full support
- ❌ **Python 3.7 and below**: Not supported

### Required Python Packages
```txt
# Core dependencies
cryptography>=3.4.8
requests>=2.25.1
pyyaml>=6.0
jinja2>=3.0.0
click>=8.0.0

# API dependencies
fastapi>=0.68.0
uvicorn>=0.15.0
pydantic>=1.8.0

# Database dependencies (if using database storage)
sqlalchemy>=1.4.0
psycopg2-binary>=2.9.0  # For PostgreSQL
pymysql>=1.0.0         # For MySQL

# Monitoring integration dependencies
prometheus-client>=0.11.0
elasticsearch>=7.13.0
```

## Operating System Specific Requirements

### Ubuntu/Debian
```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-dev build-essential
sudo apt install -y openssh-client curl wget jq
```

### CentOS/RHEL
```bash
# Install system dependencies
sudo yum update -y
sudo yum install -y python3 python3-pip python3-devel gcc gcc-c++
sudo yum install -y openssh-clients curl wget jq
```

### macOS
```bash
# Install system dependencies using Homebrew
brew install python3 openssh curl wget jq
```

## Network Requirements

### Inbound Connections
- **API Port**: 8080 (configurable)
- **Web Interface**: 8081 (configurable)
- **Prometheus Exporter**: 9090 (configurable)

### Outbound Connections
- **Remote Collection**: SSH (Port 22) to target servers
- **Monitoring Integrations**: Various ports for Prometheus, Loki, Elasticsearch
- **Webhook Notifications**: HTTPS (Port 443) to configured endpoints

### Firewall Configuration
```bash
# Example for Ubuntu/Debian with ufw
sudo ufw allow 8080  # API
sudo ufw allow 8081  # Web interface
sudo ufw allow 9090  # Prometheus exporter
sudo ufw allow 22    # SSH for remote collection
```

## Storage Requirements

### Disk Space Calculation
```
Daily Report Size = (Number of Systems × Average Report Size) × Number of Report Types
Monthly Storage = Daily Report Size × 30 × (1 + Compression Ratio)
```

### Example Calculations
- **Small Deployment**: 50 systems, 5 report types, 10KB average = ~12MB daily = ~360MB monthly (uncompressed)
- **Medium Deployment**: 500 systems, 8 report types, 10KB average = ~40MB daily = ~1.2GB monthly (uncompressed)
- **Large Deployment**: 5000 systems, 10 report types, 10KB average = ~500MB daily = ~15GB monthly (uncompressed)

### Storage Performance Recommendations
- Use SSDs for optimal performance
- Ensure at least 500 IOPS for medium deployments
- Ensure at least 2000 IOPS for large deployments

## Memory Requirements

### Runtime Memory Usage
- **Base System**: ~100MB
- **Per Active Collection**: ~10-50MB
- **API Service**: ~50-100MB
- **Cache**: Configurable (default 50MB)

### Memory Tuning
```bash
# Example JVM-like memory settings (if applicable)
export REPORTS_MAX_MEMORY=2048m
export REPORTS_CACHE_SIZE=256m
```

## Security Requirements

### User Permissions
- Run with a dedicated user account (not root)
- SSH keys with limited permissions (600)
- Configuration files with restricted access (600)

### Certificate Requirements
- If using HTTPS, obtain valid SSL certificates
- For internal deployments, self-signed certificates acceptable

## Optional Requirements

### For Enhanced Functionality
- **Docker**: For containerized deployments
- **Kubernetes**: For orchestration
- **Redis**: For session management and caching
- **PostgreSQL/MySQL**: For database storage
- **Elasticsearch**: For advanced search capabilities

### For Development
- **Git**: For source code management
- **Virtual Environment**: venv or conda
- **Testing Frameworks**: pytest, tox
- **Code Quality Tools**: flake8, black, mypy

## Compatibility Matrix

| Component | Minimum | Recommended | Status |
|-----------|---------|-------------|---------|
| Python | 3.8 | 3.10+ | ✅ Tested |
| Ubuntu | 18.04 | 20.04+ | ✅ Tested |
| CentOS | 7 | 8 | ✅ Tested |
| macOS | 10.14 | 11.0+ | ⚠️ Limited |
| Windows | WSL2 | WSL2 | ⚠️ Limited |

## Validation Script

Run this script to validate your system meets requirements:

```bash
#!/bin/bash

echo "=== Enterprise Reporting System - Requirements Validation ==="

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
if [[ $(echo $PYTHON_VERSION | cut -d. -f1) -ge 3 ]] && [[ $(echo $PYTHON_VERSION | cut -d. -f2) -ge 8 ]]; then
    echo "✅ Python version $PYTHON_VERSION: Supported"
else
    echo "❌ Python version $PYTHON_VERSION: Not supported (minimum 3.8)"
fi

# Check required packages
for cmd in ssh curl wget jq; do
    if command -v $cmd >/dev/null 2>&1; then
        echo "✅ $cmd: Available"
    else
        echo "❌ $cmd: Not found"
    fi
done

# Check disk space (at least 10GB in home directory)
DISK_SPACE=$(df -BG ~ | awk 'NR==2 {print $4}' | sed 's/G//')
if [[ $DISK_SPACE -ge 10 ]]; then
    echo "✅ Free disk space: ${DISK_SPACE}GB available"
else
    echo "⚠️ Free disk space: Only ${DISK_SPACE}GB available (recommended: 10GB+)"
fi

# Check memory
TOTAL_MEM=$(free -g | awk 'NR==2 {print $2}')
if [[ $TOTAL_MEM -ge 4 ]]; then
    echo "✅ Memory: ${TOTAL_MEM}GB available"
else
    echo "⚠️ Memory: Only ${TOTAL_MEM}GB available (recommended: 4GB+)"
fi

echo "=== Validation Complete ==="
```

## Upgrade Requirements

When upgrading from previous versions:
- Maintain backup of configuration files
- Check compatibility of custom integrations
- Update Python dependencies using `pip install --upgrade`
- Test in staging environment before production deployment