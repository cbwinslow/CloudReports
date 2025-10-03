# Troubleshooting Guide

## Overview
This guide provides comprehensive troubleshooting procedures for the Enterprise Reporting System. It includes diagnostic tools, common issues, and step-by-step resolution procedures.

## Diagnostic Tools

### Built-in Diagnostic Commands
```bash
# Run comprehensive system diagnostics
reports diagnose

# Check system status
reports status

# Validate configuration
reports configure --validate

# Test connectivity to remote systems
reports test-connectivity --target all

# Test SSH connections
reports test-ssh-connections

# Check API health
reports test-api --endpoint /health

# Run connectivity tests
reports test-connectivity
```

### System Health Check Script
```bash
#!/bin/bash
# ~/reports-diagnostics.sh

echo "=== Enterprise Reporting System Diagnostic Report ==="
echo "Generated: $(date)"
echo

# Check basic system
echo "1. SYSTEM INFORMATION"
echo "-------------------"
echo "Platform: $(uname -s)"
echo "Architecture: $(uname -m)"
echo "OS Release: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo "Uptime: $(uptime)"
echo

# Check Python environment
echo "2. PYTHON ENVIRONMENT"
echo "-------------------"
PYTHON_VERSION=$(python3 --version 2>&1)
echo "Python Version: $PYTHON_VERSION"
echo "Python Path: $(which python3)"
echo "Pip Version: $(pip3 --version 2>/dev/null || echo 'Not installed')"
echo

# Check reports installation
echo "3. REPORTS INSTALLATION"
echo "-------------------"
if command -v reports >/dev/null 2>&1; then
    echo "Reports CLI: Available"
    echo "Reports Version: $(reports --version 2>/dev/null || echo 'Unknown')"
else
    echo "Reports CLI: Not found"
fi

# Check configuration
echo
echo "4. CONFIGURATION STATUS"
echo "-------------------"
if [ -f ~/.reports/config.json ]; then
    echo "Config File: Found"
    echo "Config Valid: $(python3 -m json.tool ~/.reports/config.json >/dev/null 2>&1 && echo 'Yes' || echo 'No')"
else
    echo "Config File: Not found"
fi

# Check services
echo
echo "5. SERVICE STATUS"
echo "-------------------"
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet reports-api; then
        echo "API Service: Running"
    else
        echo "API Service: Not running"
    fi
    
    if systemctl is-active --quiet reports-web; then
        echo "Web Service: Running"
    else
        echo "Web Service: Not running"
    fi
else
    echo "SystemD: Not available (using Docker or other method?)"
fi

# Check network connectivity
echo
echo "6. NETWORK CONNECTIVITY"
echo "-------------------"
echo "API Endpoint: http://localhost:8080/api/v1/health"
if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
    echo "API Response: Healthy"
else
    echo "API Response: Unhealthy or Not Running"
fi

echo
echo "Web Interface: http://localhost:8081/"
if curl -sf http://localhost:8081/ >/dev/null 2>&1; then
    echo "Web Response: Accessible"
else
    echo "Web Response: Not Accessible"
fi

echo
echo "7. STORAGE STATUS"
echo "-------------------"
if [ -d ~/reports/data ]; then
    DATA_SIZE=$(du -sh ~/reports/data 2>/dev/null | cut -f1)
    echo "Data Directory Size: $DATA_SIZE"
    echo "Data Directory: $(ls -la ~/reports/data | wc -l) files"
else
    echo "Data Directory: Not found"
fi

echo
echo "=== Diagnostic Report Complete ==="
```

## Common Issues and Solutions

### Issue 1: API Service Won't Start

**Symptoms**:
- API service fails to start
- Port binding errors
- Configuration errors

**Diagnosis**:
```bash
# Check if port is in use
netstat -tulnp | grep :8080
lsof -i :8080

# Check service logs
sudo journalctl -u reports-api -f
# OR for Docker
docker-compose logs reports
```

**Solutions**:
1. **Port Conflict**: Change port in configuration
   ```json
   {
     "api": {
       "port": 8082
     }
   }
   ```

2. **Configuration Error**: Validate configuration
   ```bash
   reports configure --validate
   ```

3. **Permission Error**: Check file permissions
   ```bash
   chmod 600 ~/.reports/config.json
   sudo chown reports:reports ~/.reports/config.json
   ```

### Issue 2: Remote Collection Failures

**Symptoms**:
- SSH connection timeouts
- Permission denied errors
- Connection refused errors

**Diagnosis**:
```bash
# Test SSH connection manually
ssh -i ~/.ssh/reports_key -o ConnectTimeout=10 user@target-server

# Check SSH key permissions
ls -la ~/.ssh/reports_key*

# Check remote server status
reports test-ssh-connections
```

**Solutions**:
1. **SSH Key Issues**:
   ```bash
   chmod 600 ~/.ssh/reports_key
   chmod 644 ~/.ssh/reports_key.pub
   ```

2. **Firewall Issues**:
   ```bash
   # On target server
   sudo ufw allow 22/tcp
   # OR
   sudo firewall-cmd --permanent --add-service=ssh
   sudo firewall-cmd --reload
   ```

3. **SSH Configuration**:
   ```bash
   # Add to ~/.ssh/config
   Host target-server
     User reports
     IdentityFile ~/.ssh/reports_key
     ConnectTimeout 30
   ```

### Issue 3: Web Interface Not Accessible

**Symptoms**:
- 404 errors
- Connection refused
- SSL certificate errors

**Diagnosis**:
```bash
# Check if web service is running
sudo systemctl status reports-web

# Check web service logs
sudo journalctl -u reports-web -f

# Test web interface directly
curl http://localhost:8081/
```

**Solutions**:
1. **Service Not Running**: Start web service
   ```bash
   sudo systemctl start reports-web
   ```

2. **Port Configuration**: Verify port in config
   ```json
   {
     "web": {
       "port": 8081
     }
   }
   ```

3. **SSL Issues**: Check certificate paths
   ```bash
   ls -la /etc/ssl/certs/reports.crt
   ls -la /etc/ssl/private/reports.key
   ```

### Issue 4: High Memory Usage

**Symptoms**:
- System slowdown
- Memory errors
- Service crashes

**Diagnosis**:
```bash
# Check current memory usage
free -h

# Check reports process memory
ps aux | grep reports

# Monitor memory usage
top -p $(pgrep -f reports)
```

**Solutions**:
1. **Optimize Configuration**:
   ```json
   {
     "general": {
       "compression": true,
       "retention_days": 14
     }
   }
   ```

2. **Limit Concurrent Collections**:
   ```json
   {
     "collection": {
       "max_concurrent": 5,
       "batch_size": 10
     }
   }
   ```

### Issue 5: Database Performance Problems

**Symptoms**:
- Slow response times
- Query timeouts
- High disk I/O

**Diagnosis**:
```bash
# Check disk usage
df -h

# Check I/O statistics
iostat -x 1 5

# Check database file sizes
ls -lah ~/reports/data/
```

**Solutions**:
1. **Clean Old Reports**:
   ```bash
   reports cleanup --days 7
   ```

2. **Optimize Storage**:
   ```bash
   # Compress existing reports
   find ~/reports/data -name "*.json" -exec gzip {} \;
   ```

## Step-by-Step Troubleshooting Procedures

### Procedure 1: Service Startup Troubleshooting
```bash
#!/bin/bash
# Service startup troubleshooting

echo "Starting service troubleshooting procedure..."

# Step 1: Check configuration
echo "Step 1: Validating configuration..."
if ! reports configure --validate; then
    echo "❌ Configuration validation failed"
    exit 1
else
    echo "✅ Configuration is valid"
fi

# Step 2: Check file permissions
echo "Step 2: Checking file permissions..."
if [ -f ~/.reports/config.json ]; then
    PERMS=$(stat -c %a ~/.reports/config.json)
    if [ "$PERMS" = "600" ]; then
        echo "✅ Configuration file permissions are correct"
    else
        echo "⚠️ Configuration file permissions are incorrect ($PERMS), setting to 600"
        chmod 600 ~/.reports/config.json
    fi
fi

# Step 3: Check port availability
echo "Step 3: Checking port availability..."
if netstat -tulnp | grep -q :8080; then
    echo "⚠️ Port 8080 is in use, changing API port..."
    # Update configuration to use different port
    sed -i 's/"port": 8080/"port": 8082/' ~/.reports/config.json
    echo "Updated API port to 8082"
fi

if netstat -tulnp | grep -q :8081; then
    echo "⚠️ Port 8081 is in use, changing web port..."
    sed -i 's/"port": 8081/"port": 8083/' ~/.reports/config.json
    echo "Updated web port to 8083"
fi

# Step 4: Start services
echo "Step 4: Starting services..."
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl restart reports-api reports-web
    sleep 5
    
    if systemctl is-active --quiet reports-api; then
        echo "✅ API service started successfully"
    else
        echo "❌ API service failed to start"
    fi
    
    if systemctl is-active --quiet reports-web; then
        echo "✅ Web service started successfully"
    else
        echo "❌ Web service failed to start"
    fi
fi

echo "Service troubleshooting procedure completed."
```

### Procedure 2: Remote Collection Troubleshooting
```bash
#!/bin/bash
# Remote collection troubleshooting

echo "Starting remote collection troubleshooting..."

# Step 1: Check SSH key availability
if [ ! -f ~/.ssh/reports_key ]; then
    echo "❌ SSH key file does not exist"
    echo "Generate SSH key with: ssh-keygen -t rsa -b 4096 -f ~/.ssh/reports_key"
    exit 1
else
    echo "✅ SSH key found"
fi

# Step 2: Check SSH key permissions
PERMS=$(stat -c %a ~/.ssh/reports_key)
if [ "$PERMS" = "600" ]; then
    echo "✅ SSH private key permissions are correct"
else
    echo "⚠️ Fixing SSH key permissions..."
    chmod 600 ~/.ssh/reports_key
    chmod 644 ~/.ssh/reports_key.pub
fi

# Step 3: Test SSH connection to each configured server
if [ -f ~/.reports/config.json ]; then
    SERVERS=$(grep -o '"host": *"[^"]*"' ~/.reports/config.json | cut -d'"' -f4)
    
    for server in $SERVERS; do
        echo "Testing connection to $server..."
        if ssh -i ~/.ssh/reports_key -o ConnectTimeout=10 -o StrictHostKeyChecking=no $server exit; then
            echo "✅ Connection to $server successful"
        else
            echo "❌ Connection to $server failed"
        fi
    done
fi

echo "Remote collection troubleshooting completed."
```

## Advanced Diagnostic Procedures

### Performance Analysis
```bash
# Performance analysis script
cat > ~/performance_analysis.sh << 'EOF'
#!/bin/bash

echo "=== Performance Analysis ==="
echo "Date: $(date)"
echo

# Memory usage
echo "MEMORY USAGE"
echo "-----------"
free -h
echo

# CPU usage
echo "CPU USAGE"
echo "--------"
top -bn1 | head -20
echo

# Disk I/O
echo "DISK I/O"
echo "-------"
iostat -x 1 3
echo

# Network connections
echo "NETWORK CONNECTIONS (reports related)"
echo "-----------------------------------"
netstat -tulnp | grep -i reports
echo

# Process analysis
echo "TOP REPORTS PROCESSES"
echo "-------------------"
ps aux | grep reports | head -10
echo

# Log analysis
echo "RECENT LOG ENTRIES"
echo "----------------"
if [ -f /var/log/reports/app.log ]; then
    tail -20 /var/log/reports/app.log
elif [ -f ~/reports/logs/app.log ]; then
    tail -20 ~/reports/logs/app.log
fi
EOF

chmod +x ~/performance_analysis.sh
```

### Log Analysis
```bash
# Log analysis script
cat > ~/log_analysis.sh << 'EOF'
#!/bin/bash

LOG_DIR="${1:-$HOME/reports/logs}"

echo "=== Log Analysis ==="
echo "Analyzing logs in: $LOG_DIR"
echo

if [ -d "$LOG_DIR" ]; then
    # Error count
    ERROR_COUNT=$(grep -c "ERROR\|CRITICAL" "$LOG_DIR"/*.log 2>/dev/null || echo 0)
    echo "Total Errors: $ERROR_COUNT"
    
    # Recent errors
    echo
    echo "RECENT ERRORS"
    echo "-------------"
    grep -i "ERROR\|CRITICAL" "$LOG_DIR"/*.log | tail -10
    
    # Warning count
    WARNING_COUNT=$(grep -c "WARNING" "$LOG_DIR"/*.log 2>/dev/null || echo 0)
    echo
    echo "Total Warnings: $WARNING_COUNT"
    
    # Log sizes
    echo
    echo "LOG FILE SIZES"
    echo "--------------"
    ls -lah "$LOG_DIR"/*.log 2>/dev/null || echo "No log files found"
else
    echo "Log directory not found: $LOG_DIR"
fi
EOF

chmod +x ~/log_analysis.sh
```

## Recovery Procedures

### Configuration Recovery
```bash
# Configuration backup and recovery
BACKUP_DIR="$HOME/reports-backups"

# Create backup
mkdir -p "$BACKUP_DIR"
cp ~/.reports/config.json "$BACKUP_DIR/config-$(date +%Y%m%d_%H%M%S).json"

# Recovery function
recover_config() {
    local backup_file=$1
    if [ -f "$backup_file" ]; then
        cp "$backup_file" ~/.reports/config.json
        echo "Configuration recovered from: $backup_file"
        # Restart services
        sudo systemctl restart reports-api reports-web
    else
        echo "Backup file not found: $backup_file"
    fi
}
```

### Data Recovery
```bash
# Data recovery procedures
recover_data() {
    local backup_date=$1
    local backup_file="$HOME/reports-backups/data_$backup_date.tar.gz"
    
    if [ -f "$backup_file" ]; then
        echo "Recovering data from: $backup_file"
        tar -xzf "$backup_file" -C "$HOME/reports/data/"
        echo "Data recovery completed"
    else
        echo "Backup file not found: $backup_file"
    fi
}
```

## Automated Health Checks

### Health Check Script
```bash
#!/bin/bash
# ~/health_monitor.sh

HEALTH_LOG="/tmp/reports_health.log"
ALERT_EMAIL="admin@company.com"

check_health() {
    local status=0
    
    # Check API health
    if curl -sf http://localhost:8080/api/v1/health >/dev/null 2>&1; then
        echo "$(date): API - OK" >> $HEALTH_LOG
    else
        echo "$(date): API - FAILED" >> $HEALTH_LOG
        status=1
    fi
    
    # Check web interface
    if curl -sf http://localhost:8081/ >/dev/null 2>&1; then
        echo "$(date): Web - OK" >> $HEALTH_LOG
    else
        echo "$(date): Web - FAILED" >> $HEALTH_LOG
        status=1
    fi
    
    # Check disk space
    DISK_USAGE=$(df /home/reports/data | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ $DISK_USAGE -gt 85 ]; then
        echo "$(date): DISK USAGE - CRITICAL ($DISK_USAGE%)" >> $HEALTH_LOG
        status=1
    fi
    
    # Check process count
    API_COUNT=$(pgrep -f reports-api | wc -l)
    WEB_COUNT=$(pgrep -f reports-web | wc -l)
    
    if [ $API_COUNT -eq 0 ]; then
        echo "$(date): API PROCESS - NOT RUNNING" >> $HEALTH_LOG
        status=1
    fi
    
    if [ $WEB_COUNT -eq 0 ]; then
        echo "$(date): WEB PROCESS - NOT RUNNING" >> $HEALTH_LOG
        status=1
    fi
    
    # Send alert if issues found
    if [ $status -ne 0 ]; then
        echo "Health check failed. See log: $HEALTH_LOG" | mail -s "Reports System Alert" $ALERT_EMAIL
    fi
    
    return $status
}

# Run health check
check_health
```

## Support and Escalation

### When to Escalate
- Configuration validation fails repeatedly
- Database corruption occurs
- Security vulnerabilities are discovered
- Performance issues persist after optimization
- Integration problems with monitoring systems

### Support Information to Include
When requesting support, include:

1. **System Information**:
   - OS and version
   - Python version
   - Reports version
   - Hardware specifications

2. **Configuration Details**:
   - Redacted configuration file
   - Network setup
   - Integration configurations

3. **Error Information**:
   - Error messages (redacted as needed)
   - Log entries around the error
   - Steps to reproduce the issue

4. **Diagnostic Output**:
   - Output from `reports diagnose`
   - System resource usage
   - Network connectivity test results

### Support Resources
- [API Reference](api-reference.md)
- [Configuration Guide](configuration.md)
- [Community Forums](community.md)
- [Professional Support](support.md)

## Prevention Strategies

### Regular Maintenance
```bash
# Add to crontab for regular maintenance
echo "0 3 * * * reports cleanup --dry-run" | crontab -
echo "0 1 * * * reports diagnose" | crontab -
```

### Monitoring Setup
```json
{
  "alerting": {
    "providers": {
      "email": {
        "enabled": true,
        "recipients": ["admin@company.com"]
      }
    },
    "rules": [
      {
        "name": "system_health_check",
        "condition": "health.status == 'unhealthy'",
        "frequency": "5m",
        "severity": "critical"
      }
    ]
  }
}
```

This troubleshooting guide provides comprehensive procedures for diagnosing and resolving issues with the Enterprise Reporting System. For issues not covered here, consult the detailed documentation or contact support.