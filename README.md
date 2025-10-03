# Enterprise Reporting System with Cybersecurity Extensions

This system provides a comprehensive framework for collecting, analyzing, and reporting various system metrics, logs, and operational data. It includes local and remote collection capabilities with centralized configuration and data storage, enhanced with advanced cybersecurity and networking reporting modules.

## Directory Structure

```
~/reports/
├── config.json                    # Main configuration file
├── config_manager.sh              # Configuration management script
├── run_reports.sh                 # Main execution script
├── run_cybersecurity_reports.sh   # Cybersecurity reports script
├── run_reports_extended.py        # Extended reports runner with cybersecurity modules
├── CYBERSECURITY_README.md        # Documentation for cybersecurity features
├── api_server.py                  # REST API server (with cybersecurity endpoints)
├── web_server.py                  # Web dashboard server
├── system/
│   └── scripts/
│       ├── system_info.sh         # System information collection
│       └── ...
├── network/
│   └── scripts/
│       ├── network_info.sh        # Network information collection
│       └── ...
├── filesystem/
│   └── scripts/
│       ├── filesystem_info.sh     # Filesystem information collection
│       └── ...
├── error/
│   └── scripts/
│       ├── error_info.sh          # Error information collection
│       └── ...
├── log/
│   └── scripts/
│       ├── log_info.sh            # Log information collection
│       └── ...
├── container/
│   └── scripts/
│       ├── container_info.sh      # Container information collection
│       └── ...
├── security/
│   └── scripts/
│       ├── security_info.sh       # Security information collection
│       └── ...
├── process/
│   └── scripts/
│       ├── process_info.sh        # Process information collection
│       └── ...
├── hardware/
│   └── scripts/
│       ├── hardware_info.sh       # Hardware information collection
│       └── ...
├── backup/
│   └── scripts/
│       ├── backup_info.sh         # Backup information collection
│       └── ...
├── monitoring/
│   └── scripts/
│       ├── monitoring_info.sh     # Monitoring information collection
│       └── ...
├── remote/
│   └── scripts/
│       └── remote_collector.sh    # Remote collection script
├── src/
│   └── reports/
│       ├── network_traffic_analysis.py      # Network traffic analysis reports
│       ├── penetration_test_report.py       # Penetration testing results reports
│       ├── vulnerability_scan_report.py     # Vulnerability scan reports
│       ├── firewall_ids_report.py           # Firewall and IDS reports
│       ├── blue_team_report.py              # Blue team activity reports
│       ├── threat_intelligence_report.py    # Threat intelligence reports
│       ├── compliance_report.py             # Security compliance reports
│       ├── ip_logging_monitoring.py         # IP address logging and network traffic monitoring
│       ├── user_audit_monitoring.py         # User audit and activity monitoring
│       ├── io_performance_monitoring.py     # I/O throughput and performance monitoring
│       ├── gpu_monitoring.py                # GPU performance monitoring
│       ├── cpu_monitoring.py                # CPU and core performance monitoring
│       ├── system_benchmarking.py           # System benchmarking suite
│       ├── interactive_charting.py          # Interactive charting with date range selection
│       ├── process_monitoring.py            # Process monitoring and performance tracking
│       ├── storage_monitoring.py             # Storage and filesystem monitoring
│       ├── grafana_integration.py           # Grafana integration and dashboard management
│       └── opensearch_integration.py        # OpenSearch integration and log aggregation
└── data/                          # Output directory for collected reports
```

## Configuration

The system is configured through `config.json` which contains:

- General settings (output directory, retention policy, etc.)
- Report type settings (enabled/disabled, schedule, scripts)
- Remote server configurations
- Notification settings

## Usage

### Running Traditional Reports

```bash
# Run all enabled reports
./run_reports.sh full

# Run specific report type
./run_reports.sh system
./run_reports.sh network
./run_reports.sh filesystem
# ... etc

# Run remote collection
./run_reports.sh remote

# Clean old reports
./run_reports.sh clean

# List available report types
./run_reports.sh list
```

### Running Cybersecurity Reports

The system now includes comprehensive cybersecurity and networking report modules:

```bash
# Run all cybersecurity reports
./run_cybersecurity_reports.sh

# Run enhanced reports including performance monitoring
./run_enhanced_reports.sh

# Run specific cybersecurity report using the extended runner
python3 run_reports_extended.py run-single --type network_traffic
python3 run_reports_extended.py run-single --type penetration_test
python3 run_reports_extended.py run-single --type vulnerability_scan
python3 run_reports_extended.py run-single --type firewall_ids
python3 run_reports_extended.py run-single --type blue_team
python3 run_reports_extended.py run-single --type threat_intelligence
python3 run_reports_extended.py run-single --type compliance
python3 run_reports_extended.py run-single --type ip_logging
python3 run_reports_extended.py run-single --type user_audit
python3 run_reports_extended.py run-single --type io_performance
python3 run_reports_extended.py run-single --type gpu_monitoring
python3 run_reports_extended.py run-single --type cpu_monitoring
python3 run_reports_extended.py run-single --type system_benchmarking
python3 run_reports_extended.py run-single --type interactive_charting

# Run all reports including cybersecurity and performance modules
python3 run_reports_extended.py run-all

# List available report types (cybersecurity and performance)
python3 run_reports_extended.py list-types
```

### API Access to Cybersecurity and Performance Reports

The system provides RESTful API access to all reports, including cybersecurity and performance monitoring modules:

- `GET /api/v1/cybersecurity` - List available cybersecurity and performance reports
- `GET /api/v1/cybersecurity/network_traffic` - Network traffic analysis
- `GET /api/v1/cybersecurity/penetration_test` - Penetration testing results
- `GET /api/v1/cybersecurity/vulnerability_scan` - Vulnerability scan results
- `GET /api/v1/cybersecurity/firewall_ids` - Firewall and IDS activity
- `GET /api/v1/cybersecurity/blue_team` - Blue team activities
- `GET /api/v1/cybersecurity/threat_intelligence` - Threat intelligence
- `GET /api/v1/cybersecurity/compliance` - Security compliance
- `GET /api/v1/cybersecurity/ip_logging` - IP address logging and network traffic monitoring
- `GET /api/v1/cybersecurity/user_audit` - User audit and activity monitoring
- `GET /api/v1/cybersecurity/io_performance` - I/O throughput and performance monitoring
- `GET /api/v1/cybersecurity/gpu_monitoring` - GPU performance monitoring
- `GET /api/v1/cybersecurity/cpu_monitoring` - CPU and core performance monitoring
- `GET /api/v1/cybersecurity/system_benchmarking` - System benchmarking suite
- `GET /api/v1/cybersecurity/interactive_charting` - Interactive charting with date range selection

### Adding a New Server for Remote Collection

1. Edit `config.json` to add the server to the `remote_servers.servers` array:

```json
{
  "name": "my-server",
  "host": "server.example.com",
  "port": 22,
  "user": "username",
  "ssh_key": "/path/to/private/key"
}
```

2. Ensure SSH key authentication is set up between systems

3. Run remote collection:
```bash
./run_reports.sh remote
```

### Adding New Report Types

1. Create a new directory under `~/reports/` (e.g., `databases/`)
2. Create a `scripts/` subdirectory
3. Add your reporting scripts to the `scripts/` directory
4. Update `config.json` to include the new report type in the `report_types` section
5. Ensure your script follows the same pattern as existing scripts (uses config_manager.sh, outputs to the configured output directory)

## System Requirements

- Bash shell
- Core Linux utilities (ps, df, free, etc.)
- Optional: jq for enhanced JSON processing
- For container reports: Docker
- For hardware temps: lm-sensors
- For remote collection: SSH access to target systems

## Data Format

All reports are generated in JSON format for easy parsing and integration with other tools. Each report includes a timestamp and hostname for identification.

## Scheduling

Reports can be scheduled using cron or systemd timers based on the configured schedule in config.json. The system does not include a scheduler by default to allow for flexibility in deployment environments.

## Cybersecurity Features

The system now includes comprehensive cybersecurity and networking reporting capabilities:

### Network Traffic Analysis Reports
- Comprehensive analysis of network traffic patterns
- Detection of potential port scanning and DDoS attempts
- Data exfiltration detection
- Top talkers identification

### Penetration Testing Results Reports
- Executive summaries and technical findings
- Risk assessments and remediation tracking
- Compliance reporting for penetration tests
- Trend analysis of testing results

### Security Vulnerability Scan Reports
- Vulnerability categorization by severity and type
- Aging analysis of unpatched vulnerabilities
- Risk assessment based on CVSS scores
- Patch compliance and trend analysis

### Firewall and Intrusion Detection Reports
- Firewall log analysis and policy violation reports
- IDS/IPS event correlation and incident detection
- Geographic threat distribution
- Security incident identification

### Blue Team Activity Reports
- Incident response tracking and timeline
- Threat hunting activities and effectiveness
- Performance metrics for security operations
- Compliance reporting for security activities

### Threat Intelligence Reports
- Threat indicator tracking and analysis
- Threat actor profiling and campaign tracking
- Geopolitical threat landscape
- TLP compliance and sharing guidelines

### Security Compliance Reports
- Framework-specific compliance for PCI DSS, HIPAA, SOX, ISO 27001
- NIST Cybersecurity Framework implementation tracking
- CIS Controls assessment
- SOC 2 compliance reporting

## Security Considerations

- SSH keys should have appropriate permissions (600)
- Configuration files may contain sensitive information; ensure appropriate file permissions
- Remote collection requires passwordless SSH access to target systems
- API endpoints require authentication; ensure secure API key management
- Cybersecurity reports may contain sensitive information; implement appropriate access controls