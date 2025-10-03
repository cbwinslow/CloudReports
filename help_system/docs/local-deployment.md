# Local Server Deployment Guide

## Overview
This guide provides comprehensive instructions for deploying the Enterprise Reporting System on a local server. This deployment method is suitable for evaluation, development, or small-scale production environments.

## Prerequisites

### System Requirements
- **Operating System**: Ubuntu 18.04+, CentOS 7+, or RHEL 7+
- **CPU**: 2 cores (4 recommended)
- **Memory**: 4GB RAM (8GB recommended)
- **Storage**: 10GB available space (50GB+ for production)
- **Network**: Stable internet connection for updates
- **User**: Non-root user with sudo access

### Software Requirements
- Python 3.8 or higher
- Git
- SSH client/server
- Docker (optional, for containerized deployment)
- SystemD (for service management)

## Installation Methods

### Method 1: Direct Installation (Recommended)

#### Step 1: Prepare the System
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
# OR
sudo yum update -y  # CentOS/RHEL

# Install required packages
sudo apt install -y python3 python3-pip python3-venv git curl openssh-server jq
# OR
sudo yum install -y python3 python3-pip git curl openssh-server jq
```

#### Step 2: Create Dedicated User
```bash
# Create reports user
sudo useradd -r -m -s /bin/bash reports

# Add to sudo group if needed for system monitoring
sudo usermod -aG sudo reports

# Switch to reports user
sudo -u reports -i
```

#### Step 3: Install the System
```bash
# Install using pip
pip3 install --user enterprise-reporting-system

# Or install in a virtual environment
python3 -m venv ~/reports-env
source ~/reports-env/bin/activate
pip install enterprise-reporting-system
```

#### Step 4: Initialize Configuration
```bash
# Initialize with default configuration
reports-init

# Or specify custom configuration directory
reports-init --config-dir ~/reports-config
```

#### Step 5: Configure SSH for Remote Collection
```bash
# Generate SSH key for reporting
ssh-keygen -t rsa -b 4096 -C "reports@$(hostname)" -f ~/.ssh/reports_key

# Set proper permissions
chmod 600 ~/.ssh/reports_key
chmod 644 ~/.ssh/reports_key.pub

# Configure SSH server (if collecting from localhost)
sudo systemctl enable ssh
sudo systemctl start ssh
```

### Method 2: Containerized Installation

#### Step 1: Install Docker
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker reports
```

#### Step 2: Create Docker Compose File
```yaml
# ~/reports-docker-compose.yml
version: '3.8'

services:
  reports:
    image: enterprisereporting/system:latest
    container_name: enterprise-reports
    ports:
      - "8080:8080"  # API
      - "8081:8081"  # Web interface
    volumes:
      - reports-data:/app/data
      - reports-config:/app/config
      - /etc/localtime:/etc/localtime:ro
    environment:
      - REPORTS_RETENTION_DAYS=30
      - REPORTS_COMPRESSION=true
      - REPORTS_LOG_LEVEL=INFO
    restart: unless-stopped
    networks:
      - reports-net

volumes:
  reports-data:
  reports-config:

networks:
  reports-net:
    driver: bridge
```

#### Step 3: Start the Services
```bash
# Start in background
docker-compose -f ~/reports-docker-compose.yml up -d

# Check if services are running
docker-compose -f ~/reports-docker-compose.yml ps
```

## Configuration for Local Deployment

### Basic Configuration
```json
{
  "general": {
    "output_dir": "/home/reports/data",
    "retention_days": 30,
    "compression": true,
    "log_level": "INFO"
  },
  "report_types": {
    "system": {
      "enabled": true,
      "schedule": "hourly",
      "scripts": ["system_info.sh"]
    },
    "network": {
      "enabled": true,
      "schedule": "hourly",
      "scripts": ["network_info.sh"]
    },
    "filesystem": {
      "enabled": true,
      "schedule": "hourly",
      "scripts": ["filesystem_info.sh"]
    }
  },
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8080,
    "auth": {
      "enabled": true,
      "api_keys": ["your-api-key-here"]
    }
  },
  "web": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8081
  },
  "security": {
    "audit_logging": {
      "enabled": true,
      "log_file": "/home/reports/logs/audit.log",
      "retention_days": 90
    }
  }
}
```

### Remote Collection Configuration (for local host)
```json
{
  "remote_servers": {
    "enabled": true,
    "servers": [
      {
        "name": "localhost",
        "host": "127.0.0.1",
        "port": 22,
        "user": "reports",
        "ssh_key": "/home/reports/.ssh/reports_key",
        "collect_local": true
      }
    ]
  }
}
```

## Service Management

### Using SystemD (Recommended for direct installation)

#### Create Service Files
```bash
# /etc/systemd/system/reports-api.service
[Unit]
Description=Enterprise Reporting System API
After=network.target

[Service]
Type=simple
User=reports
Group=reports
WorkingDirectory=/home/reports
ExecStart=/home/reports/.local/bin/reports-api --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10
Environment=PATH=/home/reports/.local/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/systemd/system/reports-web.service
[Unit]
Description=Enterprise Reporting System Web Interface
After=network.target

[Service]
Type=simple
User=reports
Group=reports
WorkingDirectory=/home/reports
ExecStart=/home/reports/.local/bin/reports-web --host 0.0.0.0 --port 8081
Restart=always
RestartSec=10
Environment=PATH=/home/reports/.local/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
```

#### Enable and Start Services
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services to start on boot
sudo systemctl enable reports-api reports-web

# Start services
sudo systemctl start reports-api reports-web

# Check service status
sudo systemctl status reports-api reports-web
```

### Using Docker Compose (for containerized installation)

#### Start Services
```bash
# Start services
docker-compose -f ~/reports-docker-compose.yml up -d

# Check status
docker-compose -f ~/reports-docker-compose.yml ps

# View logs
docker-compose -f ~/reports-docker-compose.yml logs -f
```

## Network Configuration

### Firewall Settings
```bash
# For UFW (Ubuntu)
sudo ufw allow 8080  # API
sudo ufw allow 8081  # Web interface
sudo ufw allow 22    # SSH (if needed)
sudo ufw enable

# For firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=8081/tcp
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

### Port Configuration
```bash
# Check if ports are in use
sudo netstat -tulnp | grep :8080
sudo netstat -tulnp | grep :8081

# If ports are in use, configure different ports
# Edit ~/.reports/config.json to change ports
{
  "api": {
    "port": 8082
  },
  "web": {
    "port": 8083
  }
}
```

## Security Configuration

### User Permissions
```bash
# Set proper file permissions
chmod 700 ~/.reports
chmod 600 ~/.reports/config.json
chmod 600 ~/.ssh/reports_key
chmod 644 ~/.ssh/reports_key.pub
```

### SSL/TLS Configuration (Optional)
```bash
# Generate self-signed certificate for production
sudo mkdir -p /etc/reports/ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/reports/ssl/reports.key \
    -out /etc/reports/ssl/reports.crt

# Update configuration to use SSL
{
  "api": {
    "ssl": {
      "enabled": true,
      "cert_file": "/etc/reports/ssl/reports.crt",
      "key_file": "/etc/reports/ssl/reports.key"
    }
  }
}
```

## Data Management

### Storage Configuration
```bash
# Create dedicated storage directory
sudo mkdir -p /opt/reports-data
sudo chown reports:reports /opt/reports-data

# Update configuration to use dedicated storage
# Edit ~/.reports/config.json
{
  "general": {
    "output_dir": "/opt/reports-data"
  }
}
```

### Backup Configuration
```bash
# Create backup script
cat > ~/backup_reports.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/home/reports/backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup configuration
tar -czf "$BACKUP_DIR/config_backup_$DATE.tar.gz" ~/.reports/config.json

# Backup reports data (recent only to save space)
rsync -av --include="*/" --include="*.json" --exclude="*" \
  /home/reports/data/ "$BACKUP_DIR/reports_data_$DATE/"

echo "Backup completed: $DATE"
EOF

chmod +x ~/backup_reports.sh

# Schedule backups using cron
echo "0 2 * * * /home/reports/backup_reports.sh" | crontab -
```

## Monitoring and Maintenance

### Log Management
```bash
# Create log rotation configuration
sudo tee /etc/logrotate.d/reports << 'EOF'
/home/reports/data/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
```

### Health Checks
```bash
# Create health check script
cat > ~/health_check.sh << 'EOF'
#!/bin/bash

# Check API health
API_HEALTH=$(curl -s http://localhost:8080/api/v1/health | jq -r '.status')
if [ "$API_HEALTH" = "healthy" ]; then
    echo "$(date): API - OK"
else
    echo "$(date): API - UNHEALTHY" | tee -a /home/reports/health.log
    # Add alerting logic here
fi

# Check disk space
DISK_USAGE=$(df /home/reports/data | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "$(date): DISK USAGE HIGH - ${DISK_USAGE}%" | tee -a /home/reports/health.log
fi

# Check process status
API_COUNT=$(ps aux | grep reports-api | grep -v grep | wc -l)
WEB_COUNT=$(ps aux | grep reports-web | grep -v grep | wc -l)

if [ $API_COUNT -eq 0 ]; then
    echo "$(date): API PROCESS NOT RUNNING" | tee -a /home/reports/health.log
fi

if [ $WEB_COUNT -eq 0 ]; then
    echo "$(date): WEB PROCESS NOT RUNNING" | tee -a /home/reports/health.log
fi
EOF

chmod +x ~/health_check.sh
```

### Performance Monitoring
```bash
# Add to crontab for regular monitoring
echo "*/5 * * * * /home/reports/health_check.sh" | crontab -l | { cat; echo "*/5 * * * * /home/reports/health_check.sh"; } | crontab -
```

## Integration Configuration

### Prometheus Integration
```json
{
  "integrations": {
    "prometheus": {
      "enabled": true,
      "exporter_port": 9090,
      "metrics_path": "/metrics"
    }
  }
}
```

### Set up Prometheus to scrape metrics:
```yaml
# prometheus.yml snippet
scrape_configs:
  - job_name: 'reports'
    static_configs:
      - targets: ['localhost:9090']
```

## Testing the Installation

### Verify Installation
```bash
# Check if services are running
sudo systemctl status reports-api reports-web  # For systemd
# OR
docker-compose -f ~/reports-docker-compose.yml ps  # For Docker

# Test API
curl http://localhost:8080/api/v1/health

# Test web interface
curl http://localhost:8081/

# Run a test collection
reports run system --test
```

### Working Examples

#### Example 1: Configure Local Collection Only
```bash
# Configuration for local-only monitoring
{
  "general": {
    "output_dir": "/home/reports/data",
    "retention_days": 30,
    "compression": true
  },
  "report_types": {
    "system": {
      "enabled": true,
      "schedule": "hourly"
    },
    "process": {
      "enabled": true,
      "schedule": "hourly"
    }
  },
  "remote_servers": {
    "enabled": false
  },
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8080
  }
}
```

#### Example 2: Configure with Alerting
```json
{
  "alerting": {
    "enabled": true,
    "providers": {
      "email": {
        "enabled": true,
        "smtp_server": "localhost",
        "from": "reports@$(hostname)",
        "recipients": ["admin@company.com"]
      }
    },
    "rules": [
      {
        "name": "disk_space_warning",
        "condition": "filesystem.root.usage > 80",
        "frequency": "10m",
        "severity": "warning"
      }
    ]
  }
}
```

## Troubleshooting

### Common Issues and Solutions

#### Issue: API Service Won't Start
```bash
# Check logs
sudo journalctl -u reports-api -f  # For systemd
# OR
docker-compose -f ~/reports-docker-compose.yml logs reports  # For Docker

# Check port availability
sudo netstat -tulnp | grep :8080
```

#### Issue: SSH Connection Fails for Local Collection
```bash
# Test SSH connection
ssh -i ~/.ssh/reports_key -o ConnectTimeout=10 reports@localhost

# Check SSH server configuration
sudo systemctl status ssh

# Ensure SSH key is added to authorized_keys
cat ~/.ssh/reports_key.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

#### Issue: Web Interface Not Accessible
```bash
# Check if web service is running
sudo systemctl status reports-web

# Check firewall
sudo ufw status
# OR
sudo firewall-cmd --list-all

# Check web service logs
sudo journalctl -u reports-web -f
```

### Diagnostic Commands
```bash
# Run comprehensive diagnostics
reports diagnose

# Check system status
reports status

# Validate configuration
reports configure --validate

# Check connectivity to remote systems
reports test-connection --server localhost
```

## Scaling Considerations

### For Larger Deployments
If you plan to scale beyond the local system:

1. **Separate Database**: Consider using PostgreSQL for storage
2. **Load Balancer**: Add Nginx or Apache as a reverse proxy
3. **Monitoring**: Integrate with your existing monitoring stack
4. **Backup Strategy**: Implement automated backup procedures

### Performance Tuning
```bash
# Adjust these values in configuration for performance
{
  "general": {
    "compression": true,
    "retention_days": 14  # Reduce for high-volume systems
  },
  "report_types": {
    "system": {
      "schedule": "30m"  # Adjust collection frequency
    }
  }
}
```

## Next Steps

After successful local deployment:

1. **Configure remote targets** for cross-server monitoring
2. **Set up monitoring integrations** with your existing tools
3. **Configure alerts** for important metrics
4. **Establish backup procedures** for configuration and data
5. **Review security settings** for production use

## Support Resources

- [Troubleshooting Guide](troubleshooting.md)
- [API Reference](api-reference.md)
- [Monitoring Integrations](integrations.md)
- [Security Configuration](security.md)