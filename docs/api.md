# API Reference

## Overview

The Enterprise Reporting System provides a RESTful API for programmatic access to collected reports and system information. The API follows standard REST principles and returns JSON responses.

## Base URL

The default base URL is `http://localhost:8080/api/v1`, but this can be configured during deployment.

## Authentication

Most API endpoints require authentication. The system supports:

1. **API Keys**: Simple key-based authentication
2. **Bearer Tokens**: OAuth 2.0/JWT-based authentication
3. **Basic Auth**: Username/password authentication

### Setting Authentication Headers

```bash
# API Key
curl -H "X-API-Key: your-api-key" http://localhost:8080/api/v1/reports

# Bearer Token
curl -H "Authorization: Bearer your-jwt-token" http://localhost:8080/api/v1/reports

# Basic Auth
curl -u username:password http://localhost:8080/api/v1/reports
```

## Endpoints

### Reports

#### List All Reports
```
GET /api/v1/reports
```

**Parameters:**
- `page` (integer, optional): Page number for pagination (default: 1)
- `limit` (integer, optional): Number of items per page (default: 20, max: 100)
- `type` (string, optional): Filter by report type (e.g., "system", "network")
- `hostname` (string, optional): Filter by hostname
- `start_date` (string, optional): Filter reports after this date (ISO 8601 format)
- `end_date` (string, optional): Filter reports before this date (ISO 8601 format)

**Response:**
```json
{
  "data": [
    {
      "id": "report123",
      "type": "system",
      "hostname": "server1.example.com",
      "timestamp": "2023-01-01T10:00:00Z",
      "size_bytes": 1500,
      "url": "/api/v1/reports/report123"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "pages": 8
  }
}
```

#### Get Specific Report
```
GET /api/v1/reports/{report_id}
```

**Response:**
```json
{
  "id": "report123",
  "type": "system",
  "hostname": "server1.example.com",
  "timestamp": "2023-01-01T10:00:00Z",
  "data": {
    "cpu": {
      "model": "Intel Xeon",
      "cores": 8,
      "usage_percent": 12.5
    },
    "memory": {
      "total_gb": 16.0,
      "used_gb": 4.2,
      "usage_percent": 26.3
    }
  }
}
```

#### Delete Report
```
DELETE /api/v1/reports/{report_id}
```

**Response:**
```json
{
  "success": true,
  "message": "Report deleted successfully"
}
```

### Report Types

#### List Report Types
```
GET /api/v1/report-types
```

**Response:**
```json
{
  "data": [
    {
      "name": "system",
      "description": "System resource information",
      "enabled": true,
      "schedule": "daily"
    },
    {
      "name": "network",
      "description": "Network interface statistics",
      "enabled": true,
      "schedule": "hourly"
    }
  ]
}
```

### Systems

#### List Monitored Systems
```
GET /api/v1/systems
```

**Response:**
```json
{
  "data": [
    {
      "hostname": "server1.example.com",
      "status": "active",
      "last_report": "2023-01-01T10:00:00Z",
      "type": "remote",
      "ip_address": "192.168.1.10"
    }
  ]
}
```

#### Get System Details
```
GET /api/v1/systems/{hostname}
```

**Response:**
```json
{
  "hostname": "server1.example.com",
  "status": "active",
  "last_report": "2023-01-01T10:00:00Z",
  "type": "remote",
  "ip_address": "192.168.1.10",
  "reports": {
    "total": 45,
    "last_24h": 5,
    "types": ["system", "network", "process"]
  }
}
```

### Configuration

#### Get Configuration
```
GET /api/v1/config
```

**Response:**
```json
{
  "general": {
    "output_dir": "/home/cbwinslow/reports/data",
    "retention_days": 30,
    "compression": true
  },
  "report_types": {
    "system": {
      "enabled": true,
      "schedule": "daily"
    }
  }
}
```

#### Update Configuration
```
PUT /api/v1/config
```

**Request Body:**
```json
{
  "general": {
    "retention_days": 60
  }
}
```

**Response:**
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "updated_config": {
    "general": {
      "output_dir": "/home/cbwinslow/reports/data",
      "retention_days": 60,
      "compression": true
    }
  }
}
```

### Status

#### Health Check
```
GET /api/v1/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2023-01-01T10:00:00Z",
  "version": "1.0.0",
  "uptime_seconds": 3600
}
```

#### System Status
```
GET /api/v1/status
```

**Response:**
```json
{
  "status": "operational",
  "timestamp": "2023-01-01T10:00:00Z",
  "services": {
    "api": "running",
    "collector": "running",
    "storage": "healthy"
  },
  "stats": {
    "reports_collected": 150,
    "systems_monitored": 10,
    "api_requests_today": 245
  }
}
```

## Error Responses

All error responses follow this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": "Additional error details"
  }
}
```

### Common Error Codes

- `INVALID_REQUEST`: Request format is invalid
- `UNAUTHORIZED`: Authentication failed
- `FORBIDDEN`: Insufficient permissions
- `NOT_FOUND`: Requested resource does not exist
- `INTERNAL_ERROR`: Server-side error occurred

## Rate Limiting

The API implements rate limiting to prevent abuse:

- Anonymous requests: 100 requests per hour
- Authenticated requests: 1000 requests per hour
- Admin requests: 10000 requests per hour

Rate limits are indicated in response headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1672531200
```

## SDK Examples

### cURL

```bash
# Get all reports
curl -H "X-API-Key: your-api-key" \
     "http://localhost:8080/api/v1/reports?type=system&limit=5"

# Get specific report
curl -H "X-API-Key: your-api-key" \
     "http://localhost:8080/api/v1/reports/report123"
```

### Python

```python
import requests

class ReportsAPI:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {'X-API-Key': api_key}
    
    def get_reports(self, report_type=None, limit=20):
        params = {'limit': limit}
        if report_type:
            params['type'] = report_type
        response = requests.get(f"{self.base_url}/api/v1/reports", 
                                headers=self.headers, params=params)
        return response.json()

# Usage
api = ReportsAPI('http://localhost:8080', 'your-api-key')
reports = api.get_reports(report_type='system', limit=10)
```

### JavaScript

```javascript
class ReportsClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl;
    this.headers = {
      'X-API-Key': apiKey,
      'Content-Type': 'application/json'
    };
  }
  
  async getReports(type = null, limit = 20) {
    const params = new URLSearchParams({limit});
    if (type) params.append('type', type);
    
    const response = await fetch(`${this.baseUrl}/api/v1/reports?${params}`, {
      headers: this.headers
    });
    return await response.json();
  }
}

// Usage
const client = new ReportsClient('http://localhost:8080', 'your-api-key');
const reports = await client.getReports('system', 10);
```

## Webhooks

The system can send webhook notifications for specific events.

### Webhook Configuration

Configure webhooks in `config.json`:

```json
{
  "webhooks": [
    {
      "id": "slack-alerts",
      "url": "YOUR_SLACK_WEBHOOK_URL",
      "events": ["report_failure", "system_down"],
      "secret": "webhook-signing-secret"
    }
  ]
}
```

### Webhook Payloads

Webhook events include a signature in the `X-Signature` header for verification:

```json
{
  "event": "report_failure",
  "timestamp": "2023-01-01T10:00:00Z",
  "data": {
    "hostname": "server1.example.com",
    "report_type": "system",
    "error_message": "Connection timeout"
  }
}
```

## Examples

### Retrieve Latest System Reports

```bash
curl -H "X-API-Key: your-api-key" \
     "http://localhost:8080/api/v1/reports?type=system&limit=5"
```

### Get Report for Specific Host

```bash
curl -H "X-API-Key: your-api-key" \
     "http://localhost:8080/api/v1/reports?hostname=server1.example.com"
```

### Check System Status

```bash
curl -H "X-API-Key: your-api-key" \
     "http://localhost:8080/api/v1/status"
```