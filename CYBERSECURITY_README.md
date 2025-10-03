# Enterprise Reporting System - Cybersecurity Extensions

## Overview

This repository contains an enhanced version of the Enterprise Reporting System with comprehensive cybersecurity and networking report modules. The system provides advanced capabilities for monitoring, analyzing, and reporting on security-related activities within your infrastructure.

## New Cybersecurity Reporting Capabilities

### 1. Network Traffic Analysis Reports
Comprehensive analysis of network traffic patterns with detection of:
- Potential port scanning activities
- DDoS attempts
- Data exfiltration attempts
- Unusual connection patterns
- Top talkers identification

### 2. Penetration Testing Results Reports
Detailed reporting for penetration testing activities:
- Executive summaries
- Technical findings
- Risk assessments
- Compliance reporting
- Trend analysis
- Remediation tracking

### 3. Security Vulnerability Scan Reports
Comprehensive vulnerability assessment reporting:
- Vulnerability categorization by severity
- Aging analysis of vulnerabilities
- Risk assessment based on CVSS scores
- Patch compliance tracking
- Trend analysis over time

### 4. Firewall and Intrusion Detection Reports
Monitoring and reporting for:
- Firewall log analysis
- IDS/IPS event correlation
- Security incident identification
- Policy violation reporting
- Geographic threat distribution
- Trend analysis

### 5. Blue Team Activity Reports
Comprehensive blue team operations reporting:
- Incident response tracking
- Threat hunting activities
- Activity timeline
- Performance metrics
- Compliance reporting
- Threat hunter effectiveness

### 6. Threat Intelligence Reports
Intelligence-driven security reporting:
- Threat indicator tracking
- Threat actor analysis
- Campaign tracking
- Geopolitical threat landscape
- TLP compliance
- Trend analysis

### 7. Security Compliance Reports
Framework-specific compliance reporting:
- PCI DSS compliance
- HIPAA compliance
- SOX compliance
- ISO 27001 compliance
- NIST Cybersecurity Framework
- CIS Controls
- SOC 2 compliance

### 8. IP Address Logging and Network Traffic Monitoring
Comprehensive tracking of IP addresses and network traffic patterns:
- Internal vs external IP classification
- Geographic location mapping
- Connection pattern analysis
- Bandwidth usage tracking
- Top talkers identification

### 9. User Audit and Activity Monitoring
Comprehensive tracking of user activities and access patterns:
- Login/logout tracking
- Session monitoring
- Resource access logging
- Privileged user monitoring
- Failed login detection

### 10. I/O Throughput and Performance Monitoring
Monitoring of system I/O performance metrics:
- Disk read/write statistics
- Network I/O throughput
- Process I/O tracking
- Performance trend analysis
- System load monitoring

### 11. GPU Performance Monitoring
Comprehensive GPU utilization and health monitoring:
- GPU utilization tracking
- Memory usage monitoring
- Temperature monitoring
- Power consumption tracking
- Performance trend analysis

### 12. CPU and Core Performance Monitoring
Detailed CPU and core-specific performance tracking:
- Overall CPU utilization
- Per-core utilization
- Frequency scaling monitoring
- Temperature tracking
- Load average monitoring

### 13. System Benchmarking Suite
Comprehensive system performance benchmarking:
- CPU performance benchmarks
- Memory bandwidth tests
- Disk I/O benchmarks
- Performance comparison tools
- System capability assessment

### 14. Interactive Charting with Date Range Selection
Stock market-style interactive charts with advanced features:
- Date range selection on axes
- Zoom and pan functionality
- Multiple data series visualization
- Trend analysis tools
- Exportable chart images

## API Endpoints

The system provides RESTful API access to all reports at:

### Cybersecurity and Performance Reports API
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

### Traditional API Endpoints
- `GET /api/v1/reports` - List all reports
- `GET /api/v1/reports/{id}` - Get specific report
- `GET /api/v1/report-types` - List available report types
- `GET /api/v1/systems` - List monitored systems
- `GET /api/v1/systems/{hostname}` - Get specific system details
- `GET /api/v1/config` - System configuration
- `GET /api/v1/health` - Health check
- `GET /api/v1/status` - System status

## Usage

### Running All Reports
```bash
python3 run_reports_extended.py run-all
```

### Running Specific Reports
```bash
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
```

### Running Enhanced Reports (All Cybersecurity and Performance)
```bash
./run_enhanced_reports.sh
```
```

### Running Cybersecurity Reports Only
```bash
./run_cybersecurity_reports.sh
```

### Starting the Full System
```bash
./run_reports.sh full
```

## Architecture

The system follows a modular architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web UI        │    │   API Gateway    │    │   Data Store    │
│   Dashboard     │◄──►│   REST/GraphQL   │◄──►│   Reports       │
│   React/Angular │    │   Endpoints      │    │   JSON Files    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                      ▲                       ▲
         │                      │                       │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Real-time     │    │   Report         │    │   Security      │
│   Dashboard     │    │   Generators     │    │   Analytics     │
│   WebSocket     │    │   Engine         │    │   Engine        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                      ▲                       ▲
         │                      │                       │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Alerting      │    │   Threat Intel   │    │   Compliance    │
│   System        │    │   Platform       │    │   Frameworks    │
│   Notifications │    │   Integration    │    │   Integration   │
└─────────────────┘    └─────────────────┘     └─────────────────┘
```

## Security Features

- End-to-end encryption for sensitive data
- Multi-factor authentication
- Role-based access control (RBAC)
- API key authentication
- Audit logging
- Compliance with major security frameworks

## Compliance Standards

The system supports compliance reporting for:
- PCI DSS
- HIPAA
- SOX
- ISO 27001
- NIST Cybersecurity Framework
- CIS Controls
- GDPR
- SOC 2

## Development

The system is built with:
- Python 3.8+
- FastAPI (for enhanced future versions)
- Custom HTTP server for current implementation
- JSON-based configuration
- Modular architecture for easy extension

## Contributing

For new cybersecurity report modules, follow the existing pattern in the `/src/reports/` directory. Each module should:
1. Define appropriate data structures
2. Implement the report generation logic
3. Provide both detailed and summary views
4. Include trend analysis where applicable
5. Follow the same coding and documentation standards

## Support

For support, please open an issue in the repository or contact your system administrator.