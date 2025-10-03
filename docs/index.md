# Enterprise Reporting System Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Usage](#usage)
6. [Security](#security)
7. [Integrations](#integrations)
8. [Deployment](#deployment)
9. [Monitoring & Alerting](#monitoring--alerting)
10. [Troubleshooting](#troubleshooting)
11. [API Reference](#api-reference)
12. [Compliance](#compliance)
13. [Contributing](#contributing)

## Overview

The Enterprise Reporting System is a comprehensive solution for collecting, analyzing, and reporting system metrics, logs, and operational data. It provides both local and remote collection capabilities with centralized configuration and data storage, designed for enterprise environments requiring scalability, security, and compliance.

### Key Features
- Multi-source data collection (system metrics, network, filesystem, logs, containers, etc.)
- Centralized configuration management
- Remote server monitoring via SSH
- Integration with popular monitoring tools (Prometheus, Grafana, Loki, etc.)
- Secure credential management
- Scalable architecture supporting thousands of endpoints
- API for programmatic access
- Compliance reporting capabilities

## Architecture

The system follows a modular, microservices-inspired architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Monitoring    │    │   Collection     │    │   Processing    │
│   Interface     │◄──►│   Framework      │◄──►│   Pipeline      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                        ▲                       ▲
         │                        │                       │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Grafana/      │    │   Remote         │    │   Storage &     │
│   Visualization │    │   Collection     │    │   Export        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Core Components:
1. **Configuration Manager**: Handles system-wide settings and feature toggles
2. **Collection Engine**: Executes individual report types based on configuration
3. **Remote Collector**: Manages SSH connections to remote systems
4. **API Gateway**: Provides RESTful endpoints for data access
5. **Storage Manager**: Handles data persistence and retention policies
6. **Security Module**: Manages authentication, encryption, and access controls

## Installation

### Prerequisites
- Bash shell
- Core Linux utilities (ps, df, free, etc.)
- jq for JSON processing (recommended)
- For container reports: Docker
- For hardware temps: lm-sensors
- For remote collection: SSH access to target systems

### Quick Start
1. Clone or download the system to your target server
2. Run the setup script: `./setup.sh`
3. Configure the system by editing `config.json`
4. Run reports: `./run_reports.sh full`

## Configuration

The system is configured through `config.json` which contains settings for all aspects of operation. See the [Configuration Guide](./configuration.md) for detailed information.

## Usage

See the [Usage Guide](./usage.md) for detailed instructions on running reports, configuring schedules, and managing collected data.

### Enhanced Capabilities

The system now includes advanced monitoring and integration capabilities:

- **Process Monitoring**: Real-time tracking of system processes and resource usage
- **Storage Monitoring**: Comprehensive filesystem and storage performance tracking
- **Grafana Integration**: Seamless visualization dashboard integration
- **OpenSearch Integration**: Advanced log aggregation and search capabilities

### Running Enhanced Reports

```bash
# Run all enhanced reports with new capabilities
./run_all_enhanced_reports.sh

# Run specific enhanced reports
python3 run_reports_extended.py run-single --type process_monitoring
python3 run_reports_extended.py run-single --type storage_monitoring
python3 run_reports_extended.py run-single --type grafana_integration
python3 run_reports_extended.py run-single --type opensearch_integration

# List all available report types
python3 run_reports_extended.py list-types
```