# Configuration Guide

## Overview
This guide provides comprehensive information about configuring the Enterprise Reporting System. All configurations are managed through JSON files with the main configuration file located at `~/.reports/config.json`.

## Configuration File Structure

### Main Configuration File
```json
{
  "general": {
    "output_dir": "/home/user/reports/data",
    "retention_days": 30,
    "compression": true,
    "verbose": false,
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
    }
  },
  "integrations": {
    "prometheus": {
      "enabled": false,
      "exporter_port": 9090,
      "metrics_path": "/metrics"
    }
  },
  "remote_servers": {
    "enabled": false,
    "servers": []
  },
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8080,
    "auth": {
      "enabled": true,
      "api_keys": [],
      "jwt_secret": "auto-generated"
    }
  },
  "web": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8081
  }
}
```

## General Configuration

### Output Directory
- **Path**: `general.output_dir`
- **Default**: `~/reports/data`
- **Description**: Directory where collected reports are stored
- **Example**: `"/opt/reports/data"`

### Retention Settings
- **Path**: `general.retention_days`
- **Default**: `30`
- **Description**: Number of days to retain reports before automatic cleanup
- **Example**: `60` (60 days)

### Compression
- **Path**: `general.compression`
- **Default**: `true`
- **Description**: Whether to compress report files to save space
- **Values**: `true` or `false`

### Logging
- **Path**: `general.log_level`
- **Default**: `"INFO"`
- **Description**: Logging verbosity level
- **Values**: `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`

## Report Type Configuration

### System Reports
```json
{
  "system": {
    "enabled": true,
    "schedule": "hourly",
    "scripts": ["system_info.sh", "cpu_usage.sh", "memory_usage.sh"]
  }
}
```

**Parameters**:
- `enabled`: Enable/disable this report type
- `schedule`: How often to collect (hourly, daily, weekly)
- `scripts`: List of scripts to execute for this report type

### Network Reports
```json
{
  "network": {
    "enabled": true,
    "schedule": "hourly",
    "scripts": ["network_info.sh"]
  }
}
```

### Filesystem Reports
```json
{
  "filesystem": {
    "enabled": true,
    "schedule": "daily",
    "scripts": ["filesystem_info.sh"]
  }
}
```

## Integration Configuration

### Prometheus Integration
```json
{
  "prometheus": {
    "enabled": true,
    "exporter_port": 9090,
    "metrics_path": "/metrics",
    "namespace": "reports",
    "scrape_interval": "60s"
  }
}
```

### Loki Integration
```json
{
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
```

### Elasticsearch Integration
```json
{
  "elasticsearch": {
    "enabled": true,
    "hosts": ["http://localhost:9200"],
    "index_pattern": "reports-%Y.%m.%d",
    "username": "elastic",
    "password": "changeme"
  }
}
```

## Remote Server Configuration

### Single Remote Server
```json
{
  "remote_servers": {
    "enabled": true,
    "servers": [
      {
        "name": "web-server-01",
        "host": "192.168.1.100",
        "port": 22,
        "user": "reports",
        "ssh_key": "/home/user/.ssh/reports_key",
        "timeout": 30
      }
    ]
  }
}
```

### Multiple Remote Servers
```json
{
  "remote_servers": {
    "enabled": true,
    "servers": [
      {
        "name": "web-server-01",
        "host": "192.168.1.100",
        "port": 22,
        "user": "reports",
        "ssh_key": "/home/user/.ssh/reports_key_1"
      },
      {
        "name": "db-server-01",
        "host": "192.168.1.101",
        "port": 22,
        "user": "reports",
        "ssh_key": "/home/user/.ssh/reports_key_2"
      }
    ]
  }
}
```

## API Configuration

### Basic API Settings
```json
{
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8080,
    "auth": {
      "enabled": true,
      "api_keys": ["your-api-key-here"],
      "jwt_secret": "your-jwt-secret-here"
    },
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 100
    }
  }
}
```

### Authentication Methods
The API supports multiple authentication methods:

#### API Key Authentication
```json
{
  "auth": {
    "enabled": true,
    "api_keys": [
      "api_key_1",
      "api_key_2"
    ]
  }
}
```

#### JWT Authentication
```json
{
  "auth": {
    "enabled": true,
    "jwt_secret": "your-super-secret-jwt-key",
    "jwt_algorithm": "HS256"
  }
}
```

## Web Interface Configuration
```json
{
  "web": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8081,
    "theme": "default",
    "dashboard_refresh_interval": 30,
    "max_dashboard_items": 100
  }
}
```

## Alerting Configuration
```json
{
  "alerting": {
    "enabled": true,
    "providers": {
      "email": {
        "enabled": true,
        "smtp_server": "smtp.company.com",
        "smtp_port": 587,
        "smtp_username": "reports@company.com",
        "smtp_password": "password",
        "from": "reports@company.com",
        "recipients": ["admin@company.com"]
      },
      "webhook": {
        "enabled": false,
        "url": "https://hooks.company.com/alerts",
        "method": "POST",
        "headers": {
          "Content-Type": "application/json"
        }
      }
    },
    "rules": [
      {
        "name": "high_cpu_usage",
        "condition": "system.cpu.usage > 80",
        "frequency": "5m",
        "severity": "warning",
        "recipients": ["admin@company.com"]
      }
    ]
  }
}
```

## Security Configuration
```json
{
  "security": {
    "encryption": {
      "enabled": true,
      "algorithm": "AES-256",
      "key_location": "/home/user/.reports/encryption.key"
    },
    "audit_logging": {
      "enabled": true,
      "log_file": "/var/log/reports_audit.log",
      "retention_days": 90
    },
    "api_security": {
      "require_https": false,
      "allowed_origins": ["*"],
      "max_request_size": "10MB"
    }
  }
}
```

## Advanced Configuration Examples

### Production Configuration
```json
{
  "general": {
    "output_dir": "/opt/reports/data",
    "retention_days": 90,
    "compression": true,
    "log_level": "INFO"
  },
  "report_types": {
    "system": {
      "enabled": true,
      "schedule": "hourly"
    },
    "network": {
      "enabled": true,
      "schedule": "hourly"
    },
    "filesystem": {
      "enabled": true,
      "schedule": "hourly"
    }
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
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8080,
    "auth": {
      "enabled": true,
      "api_keys": ["your-prod-api-key"]
    }
  },
  "web": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 80,
    "theme": "enterprise"
  },
  "security": {
    "audit_logging": {
      "enabled": true,
      "log_file": "/var/log/reports/audit.log",
      "retention_days": 180
    }
  }
}
```

### Development Configuration
```json
{
  "general": {
    "output_dir": "~/reports/data",
    "retention_days": 7,
    "compression": false,
    "log_level": "DEBUG"
  },
  "report_types": {
    "system": {
      "enabled": true,
      "schedule": "test",  // Run on demand only
      "scripts": ["system_info.sh"]
    }
  },
  "api": {
    "enabled": true,
    "host": "127.0.0.1",
    "port": 8080,
    "auth": {
      "enabled": false  // Disable auth for development
    }
  },
  "security": {
    "audit_logging": {
      "enabled": false
    }
  }
}
```

## Configuration Management Commands

### Generate Default Configuration
```bash
# Generate default configuration
reports configure --generate-default

# Generate with specific output directory
reports configure --generate-default --output /path/to/config.json
```

### Validate Configuration
```bash
# Validate current configuration
reports configure --validate

# Validate specific file
reports configure --validate --config /path/to/config.json
```

### Backup Configuration
```bash
# Backup current configuration
reports configure --backup

# Restore configuration
reports configure --restore --backup-file /path/to/backup.json
```

## Environment Variables

Configuration can also be overridden using environment variables:

| Configuration Path | Environment Variable | Example |
|-------------------|---------------------|---------|
| `api.port` | `REPORTS_API_PORT` | `REPORTS_API_PORT=8080` |
| `general.retention_days` | `REPORTS_RETENTION_DAYS` | `REPORTS_RETENTION_DAYS=60` |
| `web.host` | `REPORTS_WEB_HOST` | `REPORTS_WEB_HOST=0.0.0.0` |
| `security.encryption.enabled` | `REPORTS_ENCRYPTION_ENABLED` | `REPORTS_ENCRYPTION_ENABLED=true` |

## Configuration Best Practices

### Security Best Practices
1. **Use strong passwords/API keys**: Generate using secure random methods
2. **Limit permissions**: Use dedicated user accounts with minimal required permissions
3. **Enable encryption**: Encrypt sensitive data at rest
4. **Audit logging**: Enable audit logging for compliance

### Performance Best Practices
1. **Optimize schedules**: Avoid running too many collections simultaneously
2. **Use compression**: Enable data compression to save storage
3. **Set appropriate retention**: Balance data availability with storage costs
4. **Monitor resource usage**: Regularly check system resource consumption

### Monitoring Best Practices
1. **Set up alerts**: Configure alerts for important metrics
2. **Use monitoring integrations**: Integrate with existing monitoring tools
3. **Regular reviews**: Periodically review and update configuration
4. **Backup configurations**: Regularly backup configuration files

## Troubleshooting Configuration

### Common Configuration Issues

#### Issue: Configuration Not Loading
```bash
# Check configuration file permissions
ls -la ~/.reports/config.json

# Validate configuration syntax
python -m json.tool ~/.reports/config.json
```

#### Issue: API Not Starting
```bash
# Check if port is available
netstat -tulnp | grep :8080

# Check configuration for API settings
cat ~/.reports/config.json | grep -A 10 -B 10 'api'
```

#### Issue: Remote Collection Failing
```bash
# Test SSH connection manually
ssh -i /path/to/ssh_key user@hostname

# Check remote server configuration
cat ~/.reports/config.json | grep -A 20 -B 5 'remote_servers'
```

### Configuration Validation Script
```bash
#!/bin/bash

# Configuration validation script
CONFIG_FILE="${1:-$HOME/.reports/config.json}"

echo "Validating configuration: $CONFIG_FILE"

# Check if file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "❌ Configuration file does not exist: $CONFIG_FILE"
    exit 1
fi

# Validate JSON syntax
if ! python -m json.tool "$CONFIG_FILE" > /dev/null 2>&1; then
    echo "❌ Invalid JSON syntax in configuration file"
    exit 1
fi

# Check required sections
required_sections=("general" "report_types" "api" "web")
for section in "${required_sections[@]}"; do
    if ! grep -q "\"$section\"" "$CONFIG_FILE"; then
        echo "⚠️  Missing required section: $section"
    else
        echo "✅ Found section: $section"
    fi
done

# Check API port availability
api_port=$(grep -o '"port":[[:space:]]*[0-9]*' "$CONFIG_FILE" | cut -d: -f2 | tr -d ' ')
if [ ! -z "$api_port" ]; then
    if [ $(netstat -tulnp | grep -c ":$api_port ") -gt 0 ]; then
        echo "⚠️  Port $api_port is already in use"
    else
        echo "✅ Port $api_port is available"
    fi
fi

echo "Configuration validation complete"
```

## Migration and Updates

### Migrating Configuration Between Versions
```bash
# Backup current configuration
reports configure --backup

# Check for configuration changes in new version
reports configure --check-migration

# Apply migration if needed
reports configure --migrate
```

For more detailed information about specific configuration options, refer to:
- [API Reference](api-reference.md)
- [Monitoring Integrations](integrations.md)
- [Security Configuration](security.md)
- [Deployment Guide](deployment.md)