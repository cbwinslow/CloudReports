# Remote Server Deployment Guide

## Overview
This guide provides comprehensive instructions for deploying the Enterprise Reporting System on remote servers. This deployment method is suitable for production environments where the system needs to be accessible across networks or to monitor remote systems.

## Prerequisites

### Network Requirements
- **Network Access**: Inbound access to deployment server on specified ports
- **Firewall Rules**: Rules allowing traffic on required ports
- **Domain/DNS**: Optional domain name for clean URLs
- **Load Balancer**: Optional for high availability

### Remote Server Requirements
- **Operating System**: Ubuntu 18.04+, CentOS 7+, or RHEL 7+
- **CPU**: 2 cores (4 recommended for production)
- **Memory**: 4GB RAM (8GB recommended for production)
- **Storage**: 20GB available space (adjust based on retention and volume)
- **Network**: Stable network connection with adequate bandwidth
- **Security**: SSH access to target systems for remote collection

### Security Prerequisites
- **SSH Key Authentication**: Set up for remote collection
- **SSL Certificate**: For secure API access (recommended)
- **User Accounts**: Dedicated service accounts with proper permissions
- **VPN/VPC**: Optional for enhanced security

## Installation Methods

### Method 1: Direct Installation on Remote Server

#### Step 1: Prepare the Remote Server
```bash
# Connect to remote server
ssh user@remote-server-ip

# Update system packages
sudo apt update && sudo apt upgrade -y  # Ubuntu/Debian
# OR
sudo yum update -y  # CentOS/RHEL

# Install required packages
sudo apt install -y python3 python3-pip python3-venv git curl openssh-server jq
# OR
sudo yum install -y python3 python3-pip git curl openssh-server jq
```

#### Step 2: Create Dedicated Service User
```bash
# Create reports user with system account
sudo useradd -r -m -s /bin/bash reports

# Create reports group
sudo groupadd reports

# Add user to necessary groups
sudo usermod -aG reports reports

# Switch to reports user
sudo -u reports -i
```

#### Step 3: Install the System
```bash
# Install using pip
pip3 install --user enterprise-reporting-system

# Or install in a virtual environment (recommended for production)
python3 -m venv ~/reports-env
source ~/reports-env/bin/activate
pip install enterprise-reporting-system
```

#### Step 4: Initialize Configuration
```bash
# Initialize with default configuration
reports-init --config-dir ~/.reports

# Create configuration for production
reports configure --generate-default
```

#### Step 5: Configure Firewall
```bash
# For UFW (Ubuntu)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 8080/tcp  # API
sudo ufw allow 8081/tcp  # Web interface
sudo ufw enable

# For firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=22/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --permanent --add-port=8081/tcp
sudo firewall-cmd --reload

# For iptables
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8081 -j ACCEPT
```

### Method 2: Containerized Installation on Remote Server

#### Step 1: Install Docker on Remote Server
```bash
# SSH to remote server
ssh user@remote-server-ip

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker reports

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.10.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

#### Step 2: Create Production Docker Compose File
```yaml
# ~/reports-prod-compose.yml
version: '3.8'

services:
  reports:
    image: enterprisereporting/system:latest
    container_name: enterprise-reports-prod
    ports:
      - "8080:8080"  # API
      - "8081:8081"  # Web interface
    volumes:
      - reports-data:/app/data
      - reports-config:/app/config
      - /etc/localtime:/etc/localtime:ro
    environment:
      - REPORTS_RETENTION_DAYS=90
      - REPORTS_COMPRESSION=true
      - REPORTS_LOG_LEVEL=INFO
      - REPORTS_API_HOST=0.0.0.0
      - REPORTS_WEB_HOST=0.0.0.0
    restart: unless-stopped
    networks:
      - reports-prod-net
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  reports-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/reports/data
  reports-config:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/reports/config

networks:
  reports-prod-net:
    driver: bridge
```

#### Step 3: Prepare Volumes and Configuration
```bash
# Create directories on host
sudo mkdir -p /opt/reports/{data,config}

# Set proper permissions
sudo chown -R reports:reports /opt/reports
sudo chmod 750 /opt/reports
sudo chmod 700 /opt/reports/{data,config}
```

### Method 3: Kubernetes Installation (Advanced)

#### Step 1: Prepare Kubernetes Environment
```yaml
# k8s-reports-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: enterprise-reports
  namespace: monitoring
  labels:
    app: enterprise-reports
spec:
  replicas: 1
  selector:
    matchLabels:
      app: enterprise-reports
  template:
    metadata:
      labels:
        app: enterprise-reports
    spec:
      containers:
      - name: reports
        image: enterprisereporting/system:latest
        ports:
        - containerPort: 8080
        - containerPort: 8081
        env:
        - name: REPORTS_RETENTION_DAYS
          value: "90"
        - name: REPORTS_COMPRESSION
          value: "true"
        volumeMounts:
        - name: reports-data
          mountPath: /app/data
        - name: reports-config
          mountPath: /app/config
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: reports-data
        persistentVolumeClaim:
          claimName: reports-data-pvc
      - name: reports-config
        configMap:
          name: reports-config
---
apiVersion: v1
kind: Service
metadata:
  name: reports-service
  namespace: monitoring
spec:
  selector:
    app: enterprise-reports
  ports:
    - name: api
      port: 8080
      targetPort: 8080
    - name: web
      port: 8081
      targetPort: 8081
  type: LoadBalancer
```

## Production Configuration

### Secure Configuration for Remote Deployment
```json
{
  "general": {
    "output_dir": "/opt/reports/data",
    "retention_days": 90,
    "compression": true,
    "log_level": "INFO",
    "max_file_size": "100MB"
  },
  "report_types": {
    "system": {
      "enabled": true,
      "schedule": "hourly",
      "timeout": 30,
      "max_retry": 3
    },
    "network": {
      "enabled": true,
      "schedule": "hourly",
      "timeout": 30,
      "max_retry": 3
    },
    "filesystem": {
      "enabled": true,
      "schedule": "hourly",
      "timeout": 30,
      "max_retry": 3
    }
  },
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8080,
    "ssl": {
      "enabled": true,
      "cert_file": "/etc/ssl/certs/reports.crt",
      "key_file": "/etc/ssl/private/reports.key"
    },
    "auth": {
      "enabled": true,
      "api_keys": ["your-secure-api-key-here"],
      "jwt_secret": "your-super-secure-jwt-secret-here"
    },
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 100,
      "burst": 200
    },
    "allowed_origins": ["https://yourdomain.com", "https://api.yourdomain.com"]
  },
  "web": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8081,
    "ssl": {
      "enabled": true,
      "cert_file": "/etc/ssl/certs/reports.crt",
      "key_file": "/etc/ssl/private/reports.key"
    },
    "session_timeout": 1800
  },
  "remote_servers": {
    "enabled": true,
    "servers": [
      {
        "name": "production-server-01",
        "host": "10.0.1.100",
        "port": 22,
        "user": "reports",
        "ssh_key": "/home/reports/.ssh/reports_key",
        "timeout": 30,
        "max_concurrent": 5
      },
      {
        "name": "production-server-02",
        "host": "10.0.1.101",
        "port": 22,
        "user": "reports",
        "ssh_key": "/home/reports/.ssh/reports_key",
        "timeout": 30,
        "max_concurrent": 5
      }
    ]
  },
  "integrations": {
    "prometheus": {
      "enabled": true,
      "exporter_port": 9090
    },
    "elasticsearch": {
      "enabled": true,
      "hosts": ["http://elasticsearch:9200"],
      "index_pattern": "reports-%Y.%m.%d"
    }
  },
  "security": {
    "encryption": {
      "enabled": true,
      "algorithm": "AES-256",
      "key_location": "/etc/reports/encryption.key"
    },
    "audit_logging": {
      "enabled": true,
      "log_file": "/var/log/reports/audit.log",
      "retention_days": 180,
      "max_file_size": "50MB"
    },
    "api_security": {
      "require_https": true,
      "max_request_size": "10MB",
      "allowed_origins": ["https://yourdomain.com"]
    }
  },
  "logging": {
    "level": "INFO",
    "file": "/var/log/reports/app.log",
    "max_size": "10MB",
    "backup_count": 5
  }
}
```

## SSL/TLS Configuration

### Using Let's Encrypt (Recommended)
```bash
# Install Certbot
sudo apt install certbot  # Ubuntu/Debian
# OR
sudo yum install certbot  # CentOS/RHEL

# Obtain certificate
sudo certbot certonly --standalone -d yourdomain.com

# Or for DNS validation
sudo certbot certonly --dns-cloudflare -d yourdomain.com

# Configure automatic renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Using Existing Certificate
```bash
# Copy certificate files to appropriate locations
sudo cp your_cert.crt /etc/ssl/certs/reports.crt
sudo cp your_private.key /etc/ssl/private/reports.key

# Set proper permissions
sudo chown root:root /etc/ssl/certs/reports.crt
sudo chown root:reports /etc/ssl/private/reports.key
sudo chmod 644 /etc/ssl/certs/reports.crt
sudo chmod 640 /etc/ssl/private/reports.key
```

## Service Management for Production

### Using SystemD for Direct Installation

#### Create Service Files with Security
```bash
# /etc/systemd/system/reports-api.service
[Unit]
Description=Enterprise Reporting System API
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=5
User=reports
Group=reports
WorkingDirectory=/home/reports
ExecStart=/home/reports/.local/bin/reports-api --config /home/reports/.reports/config.json
StandardOutput=journal
StandardError=journal
SyslogIdentifier=reports-api
Environment=PATH=/home/reports/.local/bin:/usr/local/bin:/usr/bin:/bin
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/reports/data

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/systemd/system/reports-web.service
[Unit]
Description=Enterprise Reporting System Web Interface
After=network.target reports-api.service

[Service]
Type=simple
Restart=always
RestartSec=5
User=reports
Group=reports
WorkingDirectory=/home/reports
ExecStart=/home/reports/.local/bin/reports-web --config /home/reports/.reports/config.json
StandardOutput=journal
StandardError=journal
SyslogIdentifier=reports-web
Environment=PATH=/home/reports/.local/bin:/usr/local/bin:/usr/bin:/bin
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/reports/data

[Install]
WantedBy=multi-user.target
```

#### Enable and Secure Services
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable reports-api reports-web

# Start services
sudo systemctl start reports-api reports-web

# Check status
sudo systemctl status reports-api reports-web

# View logs
sudo journalctl -u reports-api -f
sudo journalctl -u reports-web -f
```

### Using Docker Compose for Containerized Installation
```bash
# Start services in production mode
docker-compose -f ~/reports-prod-compose.yml up -d

# Check service status
docker-compose -f ~/reports-prod-compose.yml ps

# View logs
docker-compose -f ~/reports-prod-compose.yml logs -f

# Update services
docker-compose -f ~/reports-prod-compose.yml pull
docker-compose -f ~/reports-prod-compose.yml up -d
```

## Network and Load Balancer Configuration

### Nginx Reverse Proxy Configuration
```nginx
# /etc/nginx/sites-available/reports.conf
upstream reports_backend {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name reports.yourdomain.com;
    
    ssl_certificate /etc/ssl/certs/reports.crt;
    ssl_certificate_key /etc/ssl/private/reports.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # API endpoint
    location /api/ {
        proxy_pass http://reports_backend/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
    }
    
    # Web interface
    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name reports.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### Load Balancer Configuration
```bash
# Enable and restart Nginx
sudo a2ensite reports.conf  # Ubuntu/Debian
sudo systemctl restart nginx

# OR for CentOS/RHEL
sudo ln -s /etc/nginx/sites-available/reports.conf /etc/nginx/conf.d/
sudo systemctl restart nginx
```

## Remote Collection Setup

### Generate SSH Keys for Remote Collection
```bash
# On the main server, generate SSH key
ssh-keygen -t rsa -b 4096 -C "reports@$(hostname)" -f ~/.ssh/reports_key

# Set proper permissions
chmod 600 ~/.ssh/reports_key
chmod 644 ~/.ssh/reports_key.pub

# Copy public key to all target servers
ssh-copy-id -i ~/.ssh/reports_key.pub user@target-server-1
ssh-copy-id -i ~/.ssh/reports_key.pub user@target-server-2
```

### Test Remote Connections
```bash
# Test connection to each target server
ssh -i ~/.ssh/reports_key -o ConnectTimeout=10 user@target-server-1 'uname -a'
ssh -i ~/.ssh/reports_key -o ConnectTimeout=10 user@target-server-2 'uname -a'
```

## Data Management and Backup

### Production Data Directory
```bash
# Create and secure data directory
sudo mkdir -p /opt/reports/data
sudo chown reports:reports /opt/reports
sudo chmod 750 /opt/reports
sudo chmod 700 /opt/reports/data

# Set up log rotation
sudo tee /etc/logrotate.d/reports << 'EOF'
/opt/reports/data/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    copytruncate
    su reports reports
}
EOF
```

### Backup Strategy
```bash
# Create backup script
sudo tee /opt/reports/backup.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/opt/reports/backups"
DATE=$(date +%Y%m%d_%H%M%S)
CONFIG_BACKUP="/opt/reports/backups/config_$DATE.tar.gz"
DATA_BACKUP="/opt/reports/backups/data_$DATE.tar.gz"

mkdir -p "$BACKUP_DIR"

# Backup configuration
tar -czf "$CONFIG_BACKUP" -C /home/reports .reports/config.json

# Backup recent data only (to save space and time)
find /opt/reports/data -name "*.json" -mtime -7 -print0 | tar -czf "$DATA_BACKUP" --null -T -

echo "Backup completed: $DATE"
echo "Config backup: $CONFIG_BACKUP"
echo "Data backup: $DATA_BACKUP"

# Clean up old backups (keep last 30 days)
find /opt/reports/backups -name "config_*.tar.gz" -mtime +30 -delete
find /opt/reports/backups -name "data_*.tar.gz" -mtime +30 -delete
EOF

sudo chmod +x /opt/reports/backup.sh
sudo chown reports:reports /opt/reports/backup.sh
```

### Schedule Backups
```bash
# Add to crontab for reports user
sudo -u reports crontab -l | { cat; echo "0 2 * * * /opt/reports/backup.sh"; } | sudo -u reports crontab -
```

## Monitoring and Alerting

### Set up Health Checks
```bash
# Create health check script
sudo tee /opt/reports/health_check.sh << 'EOF'
#!/bin/bash

LOG_FILE="/opt/reports/logs/health.log"
API_URL="http://localhost:8080/api/v1/health"

# Check API health
API_STATUS=$(curl -s -o /dev/null -w "%{http_code}" $API_URL)
if [ "$API_STATUS" -eq 200 ]; then
    echo "$(date): API - Healthy" >> "$LOG_FILE"
else
    echo "$(date): API - Unhealthy (HTTP $API_STATUS)" >> "$LOG_FILE"
    # Add alerting logic here
    # Example: curl -X POST -H "Content-Type: application/json" \
    #    -d '{"text":"Reports API is unhealthy"}' \
    #    https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
fi

# Check disk space
DISK_USAGE=$(df /opt/reports/data | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 85 ]; then
    echo "$(date): DISK USAGE CRITICAL - ${DISK_USAGE}%" >> "$LOG_FILE"
fi

# Check process status
API_COUNT=$(pgrep -f reports-api | wc -l)
WEB_COUNT=$(pgrep -f reports-web | wc -l)

if [ $API_COUNT -eq 0 ]; then
    echo "$(date): API PROCESS NOT RUNNING" >> "$LOG_FILE"
fi

if [ $WEB_COUNT -eq 0 ]; then
    echo "$(date): WEB PROCESS NOT RUNNING" >> "$LOG_FILE"
fi
EOF

sudo chmod +x /opt/reports/health_check.sh
sudo chown reports:reports /opt/reports/health_check.sh
```

### Monitoring Integration
```json
{
  "integrations": {
    "prometheus": {
      "enabled": true,
      "exporter_port": 9090,
      "metrics_path": "/metrics",
      "namespace": "enterprise_reports"
    },
    "loki": {
      "enabled": true,
      "url": "http://loki:3100",
      "batch_size": 100,
      "labels": {
        "job": "reports",
        "environment": "production",
        "region": "us-east-1"
      }
    }
  }
}
```

## Security Hardening

### SSH Security
```bash
# /etc/ssh/sshd_config - Add security settings
sudo tee -a /etc/ssh/sshd_config << 'EOF'
# Security settings
MaxAuthTries 3
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
EOF

sudo systemctl restart sshd
```

### Application Security
```bash
# Set up AppArmor or SELinux profiles as appropriate
# Limit file access for reports user
sudo -u reports mkdir -p ~/.ssh
sudo -u reports chmod 700 ~/.ssh
```

## Testing the Remote Deployment

### Verification Steps
```bash
# Check if services are running
sudo systemctl status reports-api reports-web  # For systemd
# OR
docker-compose -f ~/reports-prod-compose.yml ps  # For Docker

# Test API from remote location
curl -k https://yourdomain.com/api/v1/health

# Verify SSL certificate
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Test remote collection
reports run remote --test
```

### Working Examples

#### Example 1: Multi-Region Deployment
```json
{
  "remote_servers": {
    "enabled": true,
    "servers": [
      {
        "name": "us-east-server-01",
        "host": "10.0.1.100",
        "region": "us-east-1",
        "ssh_key": "/home/reports/.ssh/reports_us_east_key"
      },
      {
        "name": "eu-west-server-01", 
        "host": "10.0.2.100",
        "region": "eu-west-1",
        "ssh_key": "/home/reports/.ssh/reports_eu_west_key"
      }
    ]
  }
}
```

#### Example 2: High Availability Configuration
```json
{
  "api": {
    "cluster_mode": true,
    "nodes": [
      "server1:8080",
      "server2:8080",
      "server3:8080"
    ],
    "consistency": "quorum"
  }
}
```

## Troubleshooting Remote Deployment

### Common Issues and Solutions

#### Issue: SSL Certificate Problems
```bash
# Check certificate validity
openssl x509 -in /etc/ssl/certs/reports.crt -text -noout

# Verify certificate matches private key
openssl x509 -noout -modulus -in /etc/ssl/certs/reports.crt | openssl md5
openssl rsa -noout -modulus -in /etc/ssl/private/reports.key | openssl md5
```

#### Issue: Remote Collection Failures
```bash
# Test SSH connection manually
ssh -i ~/.ssh/reports_key -o ConnectTimeout=10 user@target-server

# Check SSH key permissions
ls -la ~/.ssh/reports_key*
chmod 600 ~/.ssh/reports_key
chmod 644 ~/.ssh/reports_key.pub
```

#### Issue: API Not Accessible Remotely
```bash
# Check if server is bound to correct interface
netstat -tulnp | grep :8080

# Check firewall rules
sudo ufw status
# OR
sudo firewall-cmd --list-all

# Verify proxy configuration
curl -H "Host: yourdomain.com" http://localhost:8081
```

### Diagnostic Commands
```bash
# Run comprehensive diagnostics
reports diagnose --remote

# Check network connectivity
reports test-connectivity --target all

# Verify SSL configuration
reports test-ssl

# Check remote server access
reports test-remote-access --all
```

## Scaling and Maintenance

### Adding More Remote Targets
```bash
# Update configuration to add more servers
# Edit ~/.reports/config.json and add new server entries

# Restart services to apply changes
sudo systemctl restart reports-api reports-web
```

### Performance Monitoring
```bash
# Monitor system resources
top
htop
iotop

# Monitor application logs
tail -f /var/log/reports/app.log

# Monitor API performance
ab -n 1000 -c 10 https://yourdomain.com/api/v1/health
```

## Backup and Recovery

### Configuration Backup
```bash
# Backup configuration
sudo tar -czf /opt/reports/backups/config_backup_$(date +%Y%m%d).tar.gz -C /home/reports .reports/config.json
```

### Disaster Recovery Plan
```bash
# Recovery steps
# 1. Restore configuration files
# 2. Restore data (if needed)
# 3. Reinstall packages if necessary
# 4. Restart services
# 5. Verify all functionality
```

## Next Steps

After successful remote deployment:

1. **Configure monitoring integrations** with your existing monitoring stack
2. **Set up alerting** for important metrics and system events
3. **Establish backup procedures** and test recovery processes
4. **Review and document** the deployment for operational procedures
5. **Plan for scaling** as your monitoring requirements grow

## Support Resources

- [Local Deployment Guide](local-deployment.md)
- [Configuration Reference](configuration.md)
- [Security Configuration](security.md)
- [Troubleshooting Guide](troubleshooting.md)
- [API Reference](api-reference.md)