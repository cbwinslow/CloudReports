# Monitoring and Alerting

## Overview

The Enterprise Reporting System includes comprehensive monitoring and alerting capabilities to ensure system reliability, performance, and security. This guide covers configuring, managing, and utilizing these features effectively.

## System Monitoring

### Built-in Metrics

The system collects various metrics about its own operation:

#### Performance Metrics
- **Collection Time**: How long it takes to collect different report types
- **API Response Time**: Response times for API endpoints
- **Resource Usage**: CPU, memory, and disk usage of the system
- **Throughput**: Number of reports collected and processed per time period

#### Operational Metrics
- **Collection Success Rate**: Percentage of successful vs failed collections
- **System Uptime**: Duration the system has been operational
- **Queue Lengths**: Number of pending operations
- **Error Rates**: Frequency of different types of errors

### Metric Configuration

Configure metric collection in `config.json`:

```json
{
  "monitoring": {
    "metrics": {
      "collection": true,
      "performance": true,
      "errors": true,
      "system_resources": true
    },
    "collection_interval": "30s",
    "retention_days": 30,
    "export": {
      "prometheus": {
        "enabled": true,
        "port": 9090,
        "path": "/metrics"
      }
    }
  }
}
```

## Alerting System

### Alert Types

The system supports various types of alerts:

#### System Health Alerts
- **Service Down**: When the system becomes unavailable
- **High Resource Usage**: CPU, memory, or disk usage exceeds thresholds
- **Storage Full**: When storage space is running low
- **Collection Failures**: When report collections fail repeatedly

#### Data Quality Alerts
- **Missing Reports**: When expected reports don't arrive
- **Data Anomalies**: When collected data shows unexpected patterns
- **Configuration Changes**: When system configuration is changed

#### Security Alerts
- **Unauthorized Access**: Failed authentication attempts
- **Suspicious Activity**: Unusual access patterns
- **Credential Issues**: Problems with SSH keys or other credentials

### Alert Configuration

Configure alerts in `config.json`:

```json
{
  "alerting": {
    "enabled": true,
    "providers": {
      "email": {
        "enabled": true,
        "smtp_server": "smtp.company.com",
        "from": "reports@company.com",
        "recipients": ["admin@company.com", "ops@company.com"]
      },
      "webhook": {
        "enabled": true,
        "url": "https://hooks.company.com/alerts",
        "template": "default"
      },
      "slack": {
        "enabled": false,
        "webhook_url": "YOUR_SLACK_WEBHOOK_URL"
      }
    },
    "rules": [
      {
        "name": "high_cpu_usage",
        "condition": "system.cpu.usage > 90",
        "frequency": "5m",
        "severity": "critical",
        "recipients": ["admin@company.com"]
      },
      {
        "name": "collection_failure",
        "condition": "collection.failures > 5 within 10m",
        "frequency": "1m",
        "severity": "critical",
        "recipients": ["ops@company.com"]
      }
    ]
  }
}
```

## Alert Management

### Creating Alert Rules

Alert rules define when alerts should be triggered:

```json
{
  "name": "disk_space_low",
  "description": "Trigger when disk space is below 10%",
  "condition": "filesystem.root.used_percent > 90",
  "for": "5m",  // Alert after condition is true for 5 minutes
  "severity": "warning",
  "labels": {
    "team": "ops",
    "category": "infrastructure"
  },
  "annotations": {
    "summary": "Root filesystem on {{ $labels.hostname }} is {{ $value }}% full",
    "description": "The root filesystem on {{ $labels.hostname }} has reached {{ $value }}% usage which exceeds the warning threshold."
  }
}
```

### Alert Severities

- **Critical**: Immediate attention required (e.g., system down)
- **Warning**: Requires attention but not immediate action (e.g., high resource usage)
- **Info**: Informational alerts (e.g., completed maintenance tasks)

## Integration with Monitoring Tools

### Prometheus Alertmanager

Integrate with Prometheus Alertmanager for advanced alert routing:

```yaml
# alertmanager.yml
route:
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h
  receiver: 'reports-team'
receivers:
- name: 'reports-team'
  email_configs:
  - to: 'admin@company.com'
    from: 'alertmanager@company.com'
    smarthost: 'smtp.company.com:587'
```

### Grafana Alerts

Configure Grafana to use reports as a data source for dashboard alerts:

```json
{
  "dashboard": {
    "title": "System Metrics",
    "panels": [
      {
        "title": "CPU Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "reports_system_cpu_usage_percent",
            "legendFormat": "{{hostname}}"
          }
        ],
        "alert": {
          "name": "High CPU on Host",
          "message": "CPU usage is above 80%",
          "conditions": [
            {
              "evaluator": {
                "type": "gt",
                "params": [80]
              }
            }
          ]
        }
      }
    ]
  }
}
```

## Custom Alert Scripts

Create custom scripts for complex alerting logic:

```bash
#!/bin/bash
# custom_alert_scripts/cpu_spike_detector.sh

# Check for CPU usage spikes
THRESHOLD=${1:-80}
WINDOW=${2:-"5m"}

# Get average CPU usage over the last 5 minutes
AVG_CPU=$(jq -s "[.[] | select(.type == \"system\") | .data.cpu.usage_percent] | add / length" /home/cbwinslow/reports/data/system_*.json 2>/dev/null)

if [ "$AVG_CPU" != "null" ] && [ "$AVG_CPU" -gt "$THRESHOLD" ]; then
    echo "ALERT: Average CPU usage is ${AVG_CPU}% over the last ${WINDOW}"
    # Send alert via configured method
    curl -X POST -H "Content-Type: application/json" \
         -d "{\"alert\": \"High CPU\", \"value\": $AVG_CPU, \"threshold\": $THRESHOLD}" \
         "$(jq -r '.alerting.providers.webhook.url' /home/cbwinslow/reports/config.json)"
fi
```

## Dashboard Integration

### Grafana Dashboards

The system includes pre-built Grafana dashboards for monitoring:

#### System Overview Dashboard
- Collection success rates
- System resource usage
- Error rates
- Response times

#### Report-Specific Dashboards
- Detailed metrics for each report type
- Historical trends
- Comparative analysis

### Custom Dashboard Panels

Create custom panels for specific monitoring needs:

```json
{
  "dashboard": {
    "title": "Report Collection Health",
    "panels": [
      {
        "title": "Collection Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(increase(reports_collection_success_total[1h])) / (sum(increase(reports_collection_success_total[1h])) + sum(increase(reports_collection_failure_total[1h])))",
            "format": "percentunit"
          }
        ]
      }
    ]
  }
}
```

## Performance Monitoring

### Performance Baselines

Establish performance baselines for different operations:

- **Local Collection**: Expected time for local system reports
- **Remote Collection**: Expected time for remote system reports
- **API Response Times**: Expected response times for different endpoints
- **Data Processing**: Expected time for data transformation operations

### Performance Alerts

Set up alerts for performance degradation:

```json
{
  "name": "collection_performance_degradation",
  "condition": "collection.system.average_duration > 300s",
  "for": "10m",
  "severity": "warning",
  "description": "System report collection is taking longer than expected (threshold: 300s)"
}
```

## Security Monitoring

### Access Monitoring

Monitor and alert on access-related events:

- **Failed Logins**: Track failed authentication attempts
- **Unusual Access Times**: Access outside normal hours
- **Privilege Changes**: Changes to access controls
- **Configuration Changes**: Modifications to security settings

### Audit Trail Monitoring

Monitor the audit trail for security events:

```json
{
  "name": "suspicious_configuration_change",
  "condition": "event.type == 'config_change' and event.user != 'admin'",
  "severity": "warning",
  "description": "Configuration change by non-admin user"
}
```

## Alert Escalation

### Escalation Rules

Configure alert escalation for critical issues:

```json
{
  "alerting": {
    "escalation": {
      "rules": [
        {
          "alert": "service_down",
          "initial_timeout": "5m",
          "escalation_level": 2,
          "recipients": ["primary@company.com", "secondary@company.com"]
        }
      ]
    }
  }
}
```

### Silencing Rules

Temporarily silence alerts when appropriate:

```json
{
  "silencing": {
    "rules": [
      {
        "name": "maintenance_window",
        "matcher": {
          "hostname": "server1",
          "alertname": "high_cpu"
        },
        "starts_at": "2023-01-01T10:00:00Z",
        "ends_at": "2023-01-01T12:00:00Z",
        "created_by": "admin",
        "comment": "Planned maintenance"
      }
    ]
  }
}
```

## Notification Management

### Notification Channels

Configure multiple notification channels:

- **Email**: For detailed reports and non-urgent alerts
- **SMS/Slack/Teams**: For immediate notifications
- **Webhooks**: For integration with incident management systems
- **PagerDuty/VictorOps**: For escalation services

### Notification Templates

Customize notification content:

```json
{
  "templates": {
    "critical_alert": {
      "subject": "[CRITICAL] {{ .Labels.alertname }} on {{ .Labels.hostname }}",
      "body": "A critical alert has been triggered:\n\nAlert: {{ .Labels.alertname }}\nHostname: {{ .Labels.hostname }}\nValue: {{ .Value }}\nDescription: {{ .Annotations.description }}",
      "priority": "high"
    }
  }
}
```

## Testing and Validation

### Alert Testing

Test alerts without triggering real notifications:

```bash
# Simulate an alert condition
./test_alert.sh --alert-name disk_space_low --test-mode
```

### Alert Validation

Validate alert rules before applying:

```bash
# Validate alert rule syntax
./validate_alerts.sh --config /path/to/alert_rules.yaml
```

## Troubleshooting Monitoring Issues

### Common Issues

1. **Missing Metrics**: Verify collection scripts are running
2. **Alert Spam**: Adjust thresholds or evaluation periods
3. **False Positives**: Fine-tune alert conditions
4. **Delivery Failures**: Check notification configuration

### Diagnostic Commands

```bash
# Check system health
./run_reports.sh health

# Verify metric collection
curl http://localhost:9090/metrics

# Check alert status
./check_alerts.sh --status
```

## Best Practices

### Alert Design

- **Signal vs Noise**: Balance meaningful alerts with avoidable noise
- **Actionable**: Ensure alerts can be acted upon
- **Escalation**: Implement proper escalation procedures
- **Context**: Provide sufficient context for alert resolution

### Performance Monitoring

- **Baseline Establishment**: Establish performance baselines before setting thresholds
- **Trend Analysis**: Monitor trends rather than just absolute values
- **Resource Allocation**: Monitor resource usage to ensure system performance
- **Capacity Planning**: Use monitoring data for capacity planning

### Security Monitoring

- **Comprehensive Coverage**: Monitor all security-relevant events
- **Regular Review**: Regularly review and update security monitoring rules
- **Incident Response**: Integrate with incident response procedures
- **Audit Compliance**: Ensure monitoring meets audit requirements