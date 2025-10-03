# Installation Guide

## Overview
This guide provides detailed procedures for installing the Enterprise Reporting System using various methods including pip, Docker, and from source. Choose the method that best suits your environment and requirements.

## Installation Methods

### Method 1: pip Installation (Recommended for most users)

#### Prerequisites
Ensure you have Python 3.8+ installed:
```bash
python3 --version
```

#### Installation Steps
1. **Install the package**:
```bash
pip install enterprise-reporting-system
```

2. **Initialize the system**:
```bash
# Initialize with default configuration
reports-init

# Or initialize with custom configuration directory
reports-init --config-dir /etc/reports
```

3. **Verify installation**:
```bash
reports --version
reports --help
```

4. **Basic configuration**:
```bash
# Edit the configuration file
nano ~/.reports/config.json

# Or use the configuration wizard
reports configure
```

5. **Start the services**:
```bash
# Start all services
reports start

# Or start specific services
reports start api
reports start web
```

#### Post-Installation Verification
```bash
# Check if services are running
reports status

# Run a test collection
reports run system

# View available commands
reports --help
```

### Method 2: Docker Installation (Recommended for container environments)

#### Prerequisites
- Docker 19.03+
- Docker Compose (if using compose files)

#### Installation Steps
1. **Pull the latest image**:
```bash
docker pull enterprisereporting/system:latest
```

2. **Create a docker-compose file**:
```yaml
# docker-compose.yml
version: '3.8'
services:
  reports:
    image: enterprisereporting/system:latest
    container_name: enterprise-reports
    ports:
      - "8080:8080"  # API
      - "8081:8081"  # Web interface
    volumes:
      - reports-data:/app/data
      - reports-config:/app/config
    environment:
      - REPORTS_API_PORT=8080
      - REPORTS_WEB_PORT=8081
      - REPORTS_RETENTION_DAYS=30
    restart: unless-stopped

volumes:
  reports-data:
  reports-config:
```

3. **Start the services**:
```bash
# Start in foreground
docker-compose up

# Start in background
docker-compose up -d
```

4. **Access the system**:
- API: http://localhost:8080
- Web Interface: http://localhost:8081

#### Docker with Custom Configuration
```bash
# Create custom config directory
mkdir -p ./reports-config

# Copy default config
docker run --rm enterprisereporting/system:latest cat /app/config.json > ./reports-config/config.json

# Edit the configuration
nano ./reports-config/config.json

# Use custom config in compose
# docker-compose.yml
version: '3.8'
services:
  reports:
    image: enterprisereporting/system:latest
    container_name: enterprise-reports
    ports:
      - "8080:8080"
      - "8081:8081"
    volumes:
      - ./reports-data:/app/data
      - ./reports-config:/app/config
    environment:
      - REPORTS_RETENTION_DAYS=60
```

### Method 3: Source Installation (Recommended for development)

#### Prerequisites
- Git
- Python 3.8+
- Virtual environment tool (venv, conda, etc.)

#### Installation Steps
1. **Clone the repository**:
```bash
git clone https://github.com/your-org/enterprise-reporting.git
cd enterprise-reporting
```

2. **Create virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt

# Or install in development mode
pip install -e .
```

4. **Initialize the system**:
```bash
python -m reports.init

# Create default configuration
python -m reports.configure --generate-default
```

5. **Run the system**:
```bash
# Start API server
python -m reports.api --host 0.0.0.0 --port 8080

# Start web interface
python -m reports.web --host 0.0.0.0 --port 8081

# Or run all services in development mode
python -m reports.dev --all
```

## Platform-Specific Installation

### Ubuntu/Debian
```bash
# Update system
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl openssh-client

# Create a dedicated user
sudo useradd -r -m -s /bin/bash reports
sudo -u reports -i

# Install using pip
pip install --user enterprise-reporting-system
reports-init
```

### CentOS/RHEL
```bash
# Install prerequisites
sudo yum update -y
sudo yum install -y python3 python3-pip git curl openssh-clients

# Install using pip
pip3 install --user enterprise-reporting-system
~/.local/bin/reports-init
```

### macOS
```bash
# Install Python via Homebrew
brew install python3 git openssh curl

# Install the package
pip3 install enterprise-reporting-system
reports-init
```

## Production Installation

### Using Systemd (Linux)
Create systemd service files for automatic startup:

```bash
# /etc/systemd/system/reports-api.service
[Unit]
Description=Enterprise Reporting System API
After=network.target

[Service]
Type=simple
User=reports
Group=reports
WorkingDirectory=/home/reports
ExecStart=/home/reports/.local/bin/reports-api --host 0.0.0.0 --port 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# /etc/systemd/system/reports-web.service
[Unit]
Description=Enterprise Reporting System Web Interface
After=network.target

[Service]
Type=simple
User=reports
Group=reports
WorkingDirectory=/home/reports
ExecStart=/home/reports/.local/bin/reports-web --host 0.0.0.0 --port 8081
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start services:
```bash
sudo systemctl daemon-reload
sudo systemctl enable reports-api reports-web
sudo systemctl start reports-api reports-web
```

### Using Docker Compose for Production
```bash
# docker-compose.prod.yml
version: '3.8'
services:
  reports:
    image: enterprisereporting/system:latest
    container_name: enterprise-reports-prod
    ports:
      - "80:8081"  # Web interface on port 80
    volumes:
      - reports-data:/app/data
      - reports-config:/app/config
      - /etc/localtime:/etc/localtime:ro
    environment:
      - REPORTS_RETENTION_DAYS=90
      - REPORTS_COMPRESSION=true
      - REPORTS_LOG_LEVEL=INFO
    restart: unless-stopped
    networks:
      - reports-net

networks:
  reports-net:
    driver: bridge

volumes:
  reports-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/reports-data
  reports-config:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/reports-config
```

## Configuration After Installation

### Basic Configuration
```bash
# Generate default configuration
reports configure --generate-default

# Edit configuration
nano ~/.reports/config.json
```

### Sample Configuration
```json
{
  "general": {
    "output_dir": "/home/user/reports/data",
    "retention_days": 30,
    "compression": true,
    "verbose": false
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
      "schedule": "daily"
    }
  },
  "integrations": {
    "prometheus": {
      "enabled": false,
      "exporter_port": 9090
    }
  },
  "remote_servers": {
    "enabled": false,
    "servers": []
  }
}
```

### SSH Key Setup (for remote collection)
```bash
# Generate SSH key for reporting
ssh-keygen -t rsa -b 4096 -C "reports@yourdomain.com" -f ~/.ssh/reports_key

# Set proper permissions
chmod 600 ~/.ssh/reports_key
chmod 644 ~/.ssh/reports_key.pub

# Add public key to target servers
ssh-copy-id -i ~/.ssh/reports_key.pub user@target-server
```

## Verification and Testing

### Verify Installation
```bash
# Check installation
reports --version
python -c "import reports; print('Reports module loaded successfully')"

# Check configuration
reports configure --validate
```

### Test Basic Functionality
```bash
# Run a quick test collection
reports run system --test

# Check if API is responding
curl http://localhost:8080/api/v1/health

# Check web interface
curl http://localhost:8081/
```

### Common Post-Installation Tasks
```bash
# Set up automated collection (using cron)
echo "0 * * * * /home/user/.local/bin/reports run all" | crontab -

# Or using systemd timers
# Create timer files for automated execution
```

## Troubleshooting Installation

### Common Issues and Solutions

#### Issue: Permission Denied
```bash
# Check and fix permissions
chmod +x ~/.local/bin/reports*
chmod 600 ~/.reports/config.json
```

#### Issue: Python Path Not Found
```bash
# Add to PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### Issue: Port Already in Use
```bash
# Change ports in configuration
# Edit ~/.reports/config.json
{
  "api": {
    "port": 8082
  },
  "web": {
    "port": 8083
  }
}
```

#### Issue: Dependencies Not Found
```bash
# Install in a virtual environment
python3 -m venv reports_env
source reports_env/bin/activate
pip install enterprise-reporting-system
```

## Uninstallation

### pip Installation
```bash
pip uninstall enterprise-reporting-system

# Remove configuration
rm -rf ~/.reports/

# Remove data (optional)
rm -rf ~/reports/data/
```

### Docker Installation
```bash
# Stop and remove containers
docker-compose down -v

# Remove images
docker rmi enterprisereporting/system:latest

# Remove volumes (optional)
docker volume rm reports-data reports-config
```

### Source Installation
```bash
# Remove source directory
rm -rf ./enterprise-reporting/

# Remove virtual environment
rm -rf ./venv/
```

## Upgrade Procedures

### pip Upgrade
```bash
pip install --upgrade enterprise-reporting-system

# Backup configuration before upgrade
cp -r ~/.reports/config.json ~/.reports/config.json.backup

# Run upgrade scripts if available
reports upgrade
```

### Docker Upgrade
```bash
# Pull latest image
docker pull enterprisereporting/system:latest

# Recreate containers
docker-compose up -d --no-deps --force-recreate reports
```

## Support and Resources

- [Quick Start Guide](quick-start.md)
- [Configuration Reference](configuration.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Community Support](support.md)