"""
Command Line Interface for Enterprise Reporting System
"""

import click
import sys
from pathlib import Path

# Add the reports package to the path
sys.path.insert(0, str(Path(__file__).parent))

@click.group()
@click.version_option(version='1.0.0')
def main():
    """Enterprise Reporting System - Comprehensive monitoring and reporting solution"""
    pass

@main.command()
@click.option('--config-dir', default='~/.reports', help='Configuration directory')
def init(config_dir):
    """Initialize the reporting system with default configuration"""
    import os
    from pathlib import Path
    
    config_path = Path(config_dir).expanduser()
    config_path.mkdir(parents=True, exist_ok=True)
    
    # Create default configuration
    default_config = {
        "general": {
            "output_dir": str(config_path / "data"),
            "retention_days": 30,
            "compression": True,
            "verbose": False
        },
        "report_types": {
            "system": {
                "enabled": True,
                "schedule": "hourly"
            },
            "network": {
                "enabled": True,
                "schedule": "hourly"
            }
        },
        "api": {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 8080
        },
        "web": {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 8081
        }
    }
    
    # Create data directory
    data_dir = config_path / "data"
    data_dir.mkdir(exist_ok=True)
    
    # Write default config (simplified, in a real implementation you'd use JSON)
    config_file = config_path / "config.json"
    if not config_file.exists():
        import json
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
    
    click.echo(f"Enterprise Reporting System initialized in {config_path}")
    click.echo(f"Configuration file created: {config_file}")
    click.echo(f"Data directory created: {data_dir}")

@main.command()
def status():
    """Show system status"""
    click.echo("Enterprise Reporting System Status:")
    click.echo("- API: Not Running")
    click.echo("- Web Interface: Not Running")
    click.echo("- Collection: Not Active")
    click.echo("- Database: Not Connected")

@main.command()
def version():
    """Show version information"""
    click.echo("Enterprise Reporting System v1.0.0")
    click.echo("Copyright (c) 2025 Your Organization")

if __name__ == '__main__':
    main()