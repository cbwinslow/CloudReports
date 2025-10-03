# Makefile for Enterprise Reporting System

# Variables
PYTHON := python3
PIP := pip3
VENV := venv
VENV_BIN := $(VENV)/bin
PACKAGE_NAME := enterprise-reporting-system
VERSION := 1.0.0

# Install paths
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
DOCDIR ?= $(DATADIR)/doc/$(PACKAGE_NAME)

# Directories
SRC_DIR := src
DIST_DIR := dist
BUILD_DIR := build

.PHONY: all install uninstall clean dist test help check

all: help

help:
	@echo "Enterprise Reporting System Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make install          - Install the package"
	@echo "  make uninstall        - Uninstall the package"
	@echo "  make develop          - Install in development mode"
	@echo "  make dist             - Create distribution packages"
	@echo "  make test             - Run tests"
	@echo "  make clean            - Clean build artifacts"
	@echo "  make check            - Run code quality checks"
	@echo "  make help             - Show this help message"
	@echo ""

# Create virtual environment
$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(VENV_BIN)/pip install --upgrade pip setuptools wheel

# Install dependencies
deps: $(VENV)
	$(VENV_BIN)/pip install -r requirements.txt

# Install the package
install: deps
	$(VENV_BIN)/pip install .
	@echo "Enterprise Reporting System installed successfully"

# Install in development mode
develop: deps
	$(VENV_BIN)/pip install -e .
	@echo "Enterprise Reporting System installed in development mode"

# Build distribution packages
dist: deps
	$(VENV_BIN)/pip install build
	$(VENV_BIN)/python -m build
	@echo "Distribution packages created in $(DIST_DIR)/"

# Run tests
test: deps
	$(VENV_BIN)/pip install pytest
	$(VENV_BIN)/python -m pytest tests/ -v
	@echo "Tests completed"

# Run code quality checks
check: deps
	$(VENV_BIN)/pip install flake8 black mypy
	$(VENV_BIN)/flake8 src/ --max-line-length=88
	$(VENV_BIN)/black --check src/
	$(VENV_BIN)/mypy src/
	@echo "Code quality checks completed"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(DIST_DIR) *.egg-info __pycache__ */__pycache__
	rm -rf $(VENV)
	@echo "Build artifacts cleaned"

# Uninstall the package
uninstall:
	$(VENV_BIN)/pip uninstall $(PACKAGE_NAME) -y || echo "Package not installed in venv"
	pip uninstall $(PACKAGE_NAME) -y || echo "Package not installed globally"
	@echo "Enterprise Reporting System uninstalled"

# Install system-wide (requires sudo)
install-system: dist
	sudo pip install dist/$(PACKAGE_NAME)-$(VERSION)*.whl
	@echo "Enterprise Reporting System installed system-wide"

# Create a systemd service files
systemd:
	@echo "[Unit]" > reports-api.service
	@echo "Description=Enterprise Reporting System API" >> reports-api.service
	@echo "After=network.target" >> reports-api.service
	@echo "" >> reports-api.service
	@echo "[Service]" >> reports-api.service
	@echo "Type=simple" >> reports-api.service
	@echo "User=reports" >> reports-api.service
	@echo "Group=reports" >> reports-api.service
	@echo "WorkingDirectory=/opt/reports" >> reports-api.service
	@echo "ExecStart=/opt/reports/venv/bin/reports-api --host 0.0.0.0 --port 8080" >> reports-api.service
	@echo "Restart=always" >> reports-api.service
	@echo "RestartSec=10" >> reports-api.service
	@echo "" >> reports-api.service
	@echo "[Install]" >> reports-api.service
	@echo "WantedBy=multi-user.target" >> reports-api.service
	@echo "" >> reports-api.service
	@echo "API systemd service file created: reports-api.service"

	@echo "[Unit]" > reports-web.service
	@echo "Description=Enterprise Reporting System Web Interface" >> reports-web.service
	@echo "After=network.target reports-api.service" >> reports-web.service
	@echo "" >> reports-web.service
	@echo "[Service]" >> reports-web.service
	@echo "Type=simple" >> reports-web.service
	@echo "User=reports" >> reports-web.service
	@echo "Group=reports" >> reports-web.service
	@echo "WorkingDirectory=/opt/reports" >> reports-web.service
	@echo "ExecStart=/opt/reports/venv/bin/reports-web --host 0.0.0.0 --port 8081" >> reports-web.service
	@echo "Restart=always" >> reports-web.service
	@echo "RestartSec=10" >> reports-web.service
	@echo "" >> reports-web.service
	@echo "[Install]" >> reports-web.service
	@echo "WantedBy=multi-user.target" >> reports-web.service
	@echo "" >> reports-web.service
	@echo "Web Interface systemd service file created: reports-web.service"

# Create configuration files
config:
	@mkdir -p ~/.reports
	@echo '{' > ~/.reports/config.json
	@echo '  "general": {' >> ~/.reports/config.json
	@echo '    "output_dir": "~/reports/data",' >> ~/.reports/config.json
	@echo '    "retention_days": 30,' >> ~/.reports/config.json
	@echo '    "compression": true' >> ~/.reports/config.json
	@echo '  },' >> ~/.reports/config.json
	@echo '  "api": {' >> ~/.reports/config.json
	@echo '    "enabled": true,' >> ~/.reports/config.json
	@echo '    "host": "0.0.0.0",' >> ~/.reports/config.json
	@echo '    "port": 8080' >> ~/.reports/config.json
	@echo '  },' >> ~/.reports/config.json
	@echo '  "web": {' >> ~/.reports/config.json
	@echo '    "enabled": true,' >> ~/.reports/config.json
	@echo '    "host": "0.0.0.0",' >> ~/.reports/config.json
	@echo '    "port": 8081' >> ~/.reports/config.json
	@echo '  }' >> ~/.reports/config.json
	@echo '}' >> ~/.reports/config.json
	@chmod 600 ~/.reports/config.json
	@echo "Default configuration created in ~/.reports/config.json"

# Initialize the system
init: config install
	@mkdir -p ~/reports/data
	@echo "Enterprise Reporting System initialized"
	@echo "Configuration: ~/.reports/config.json"
	@echo "Data directory: ~/reports/data"