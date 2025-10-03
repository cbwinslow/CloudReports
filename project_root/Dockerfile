# Dockerfile for Enterprise Reporting System
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REPORTS_HOME=/app \
    REPORTS_DATA=/app/data \
    REPORTS_CONFIG=/app/config

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-client \
    curl \
    jq \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR $REPORTS_HOME

# Create non-root user
RUN useradd -m -s /bin/bash -d $REPORTS_HOME reports \
    && chown -R reports:reports $REPORTS_HOME

# Copy requirements and install Python dependencies
COPY --chown=reports:reports requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Install the Enterprise Reporting System
COPY --chown=reports:reports . .

# Install the package
RUN pip install .

# Create data and config directories
RUN mkdir -p $REPORTS_DATA $REPORTS_CONFIG \
    && chown -R reports:reports $REPORTS_HOME

# Switch to non-root user
USER reports

# Expose ports
EXPOSE 8080 8081

# Default command
CMD ["sh", "-c", "reports-init && reports-api --host 0.0.0.0 --port 8080 & reports-web --host 0.0.0.0 --port 8081"]