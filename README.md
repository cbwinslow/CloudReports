# Comprehensive Reporting System

This system provides a comprehensive framework for collecting, analyzing, and reporting various system metrics, logs, and operational data. It includes local and remote collection capabilities with centralized configuration and data storage.

## Directory Structure

```
~/reports/
├── config.json                 # Main configuration file
├── config_manager.sh           # Configuration management script
├── run_reports.sh              # Main execution script
├── system/
│   └── scripts/
│       ├── system_info.sh      # System information collection
│       └── ...
├── network/
│   └── scripts/
│       ├── network_info.sh     # Network information collection
│       └── ...
├── filesystem/
│   └── scripts/
│       ├── filesystem_info.sh  # Filesystem information collection
│       └── ...
├── error/
│   └── scripts/
│       ├── error_info.sh       # Error information collection
│       └── ...
├── log/
│   └── scripts/
│       ├── log_info.sh         # Log information collection
│       └── ...
├── container/
│   └── scripts/
│       ├── container_info.sh   # Container information collection
│       └── ...
├── security/
│   └── scripts/
│       ├── security_info.sh    # Security information collection
│       └── ...
├── process/
│   └── scripts/
│       ├── process_info.sh     # Process information collection
│       └── ...
├── hardware/
│   └── scripts/
│       ├── hardware_info.sh    # Hardware information collection
│       └── ...
├── backup/
│   └── scripts/
│       ├── backup_info.sh      # Backup information collection
│       └── ...
├── monitoring/
│   └── scripts/
│       ├── monitoring_info.sh  # Monitoring information collection
│       └── ...
├── remote/
│   └── scripts/
│       └── remote_collector.sh # Remote collection script
└── data/                       # Output directory for collected reports
```

## Configuration

The system is configured through `config.json` which contains:

- General settings (output directory, retention policy, etc.)
- Report type settings (enabled/disabled, schedule, scripts)
- Remote server configurations
- Notification settings

## Usage

### Running Reports

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

## Security Considerations

- SSH keys should have appropriate permissions (600)
- Configuration files may contain sensitive information; ensure appropriate file permissions
- Remote collection requires passwordless SSH access to target systems