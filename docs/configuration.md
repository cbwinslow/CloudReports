# Configuration Guide

## Overview

The Enterprise Reporting System is configured using a centralized JSON configuration file located at `~/reports/config.json`. This document details all configuration options and their purposes.

## General Settings

```json
{
  "general": {
    "output_dir": "/home/cbwinslow/reports/data",
    "retention_days": 30,
    "compression": true,
    "verbose": true
  }
}
```

- `output_dir`: Directory where collected reports will be stored
- `retention_days`: Number of days to retain reports before automatic cleanup
- `compression`: Whether to compress collected data files
- `verbose`: Enable detailed logging during report collection

## Report Types Configuration

Each report type can be enabled/disabled and configured with specific parameters:

```json
"report_types": {
  "system": {
    "enabled": true,
    "schedule": "daily",
    "scripts": ["system_info.sh"]
  }
}
```

- `enabled`: Whether this report type is active
- `schedule`: How often to collect this report type (not implemented in basic system)
- `scripts`: List of scripts to execute for this report type

## Remote Server Configuration

Configure remote servers for data collection:

```json
"remote_servers": {
  "enabled": false,
  "servers": [
    {
      "name": "server1",
      "host": "server1.example.com",
      "port": 22,
      "user": "username",
      "ssh_key": "/path/to/private/key"
    }
  ]
}
```

## Security Configuration

Configure security-related settings:

```json
"security": {
  "encryption": {
    "enabled": true,
    "algorithm": "aes-256-cbc",
    "key_location": "/path/to/encryption/key"
  },
  "credentials": {
    "file": "/path/to/secure/credentials.json",
    "permissions": "600"
  }
}
```

## Notifications

Configure alerting and notification:

```json
"notifications": {
  "enabled": false,
  "email": {
    "smtp_server": "smtp.example.com",
    "from": "reports@example.com",
    "to": ["admin@example.com"]
  },
  "webhook": {
    "enabled": false,
    "url": "https://hooks.example.com/webhook"
  }
}
```

## Integration Configuration

Configure integration with external systems:

```json
"integrations": {
  "prometheus": {
    "enabled": false,
    "exporter_port": 9090,
    "metrics_path": "/metrics"
  },
  "loki": {
    "enabled": false,
    "url": "http://loki:3100",
    "labels": {
      "job": "reports"
    }
  }
}
```