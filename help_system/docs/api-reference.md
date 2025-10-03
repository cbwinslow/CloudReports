# API Reference

## Overview
The Enterprise Reporting System provides a comprehensive RESTful API for programmatic access to reports, system configuration, and monitoring data. All API endpoints require authentication and return JSON responses.

## Base URL
```
https://your-domain.com/api/v1/
```

For local installations:
```
http://localhost:8080/api/v1/
```

## Authentication

### API Key Authentication
Include an API key in the request headers:
```
X-API-Key: your-api-key-here
```

### Bearer Token Authentication
For JWT-based authentication:
```
Authorization: Bearer your-jwt-token
```

### Basic Authentication
As an alternative:
```
Authorization: Basic base64encodedcredentials
```

## Global Headers
All requests should include:
- `Content-Type: application/json` for POST/PUT requests
- Appropriate authentication headers

## Response Format

### Success Response
```json
{
  "success": true,
  "data": { /* response data */ },
  "timestamp": "2023-01-01T10:00:00Z",
  "version": "1.0.0"
}
```

### Error Response
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": "Additional error details"
  },
  "timestamp": "2023-01-01T10:00:00Z"
}
```

## Common HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `429` - Too Many Requests
- `500` - Internal Server Error

## Endpoints

### Reports

#### GET /api/v1/reports
**Description**: List collected reports with optional filtering and pagination

**Parameters**:
- `page` (integer, optional): Page number (default: 1)
- `limit` (integer, optional): Items per page (default: 20, max: 100)
- `type` (string, optional): Report type filter (system, network, filesystem, etc.)
- `hostname` (string, optional): Hostname filter
- `start_date` (string, optional): Filter reports after this date (ISO 8601 format)
- `end_date` (string, optional): Filter reports before this date (ISO 8601 format)
- `sort` (string, optional): Sort field (timestamp, hostname, type)
- `order` (string, optional): Sort order (asc, desc)

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/reports?type=system&limit=5"
```

**Example Response**:
```json
{
  "success": true,
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
    "limit": 5,
    "total": 150,
    "pages": 30
  },
  "timestamp": "2023-01-01T10:00:00Z"
}
```

#### GET /api/v1/reports/{id}
**Description**: Get a specific report by ID

**Parameters**:
- `id` (path): Report ID

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/reports/report123"
```

**Example Response**:
```json
{
  "success": true,
  "data": {
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
  },
  "timestamp": "2023-01-01T10:00:00Z"
}
```

#### DELETE /api/v1/reports/{id}
**Description**: Delete a specific report

**Parameters**:
- `id` (path): Report ID

**Example Request**:
```bash
curl -X DELETE -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/reports/report123"
```

**Example Response**:
```json
{
  "success": true,
  "message": "Report deleted successfully",
  "timestamp": "2023-01-01T10:00:00Z"
}
```

### Report Types

#### GET /api/v1/report-types
**Description**: List available report types

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/report-types"
```

**Example Response**:
```json
{
  "success": true,
  "data": [
    {
      "name": "system",
      "description": "System resource information",
      "enabled": true,
      "schedule": "hourly",
      "supported_fields": [
        "cpu_usage_percent",
        "memory_usage_percent",
        "disk_usage_percent"
      ]
    },
    {
      "name": "network",
      "description": "Network interface statistics",
      "enabled": true,
      "schedule": "hourly",
      "supported_fields": [
        "interface_name",
        "rx_bytes",
        "tx_bytes"
      ]
    }
  ],
  "timestamp": "2023-01-01T10:00:00Z"
}
```

### Systems

#### GET /api/v1/systems
**Description**: List monitored systems

**Parameters**:
- `status` (string, optional): Filter by status (active, inactive, warning)

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/systems"
```

**Example Response**:
```json
{
  "success": true,
  "data": [
    {
      "hostname": "server1.example.com",
      "status": "active",
      "last_report": "2023-01-01T10:00:00Z",
      "type": "physical",
      "os": "Ubuntu 20.04",
      "ip_address": "192.168.1.100",
      "reports_collected": 45
    }
  ],
  "timestamp": "2023-01-01T10:00:00Z"
}
```

#### GET /api/v1/systems/{hostname}
**Description**: Get details about a specific system

**Parameters**:
- `hostname` (path): System hostname

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/systems/server1.example.com"
```

**Example Response**:
```json
{
  "success": true,
  "data": {
    "hostname": "server1.example.com",
    "status": "active",
    "last_report": "2023-01-01T10:00:00Z",
    "type": "physical",
    "os": "Ubuntu 20.04",
    "ip_address": "192.168.1.100",
    "cpu_count": 8,
    "memory_gb": 32,
    "reports": {
      "total": 45,
      "last_24h": 5,
      "types": ["system", "network", "filesystem"]
    }
  },
  "timestamp": "2023-01-01T10:00:00Z"
}
```

### Configuration

#### GET /api/v1/config
**Description**: Get current system configuration

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/config"
```

**Example Response**:
```json
{
  "success": true,
  "data": {
    "general": {
      "output_dir": "/home/reports/data",
      "retention_days": 30,
      "compression": true
    },
    "report_types": {
      "system": {
        "enabled": true,
        "schedule": "hourly"
      }
    }
  },
  "timestamp": "2023-01-01T10:00:00Z"
}
```

#### PUT /api/v1/config
**Description**: Update system configuration

**Request Body**:
```json
{
  "general": {
    "retention_days": 60
  }
}
```

**Example Request**:
```bash
curl -X PUT -H "X-API-Key: your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"general": {"retention_days": 60}}' \
     "https://api.example.com/api/v1/config"
```

**Example Response**:
```json
{
  "success": true,
  "message": "Configuration updated successfully",
  "data": {
    "general": {
      "output_dir": "/home/reports/data",
      "retention_days": 60,
      "compression": true
    }
  },
  "timestamp": "2023-01-01T10:00:00Z"
}
```

### Integrations

#### GET /api/v1/integrations
**Description**: List configured integrations

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/integrations"
```

**Example Response**:
```json
{
  "success": true,
  "data": [
    {
      "name": "prometheus",
      "enabled": true,
      "status": "connected",
      "endpoint": "http://localhost:9090"
    },
    {
      "name": "loki",
      "enabled": false,
      "status": "disconnected"
    }
  ],
  "timestamp": "2023-01-01T10:00:00Z"
}
```

### Monitoring & Health

#### GET /api/v1/health
**Description**: Get system health status

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/health"
```

**Example Response**:
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2023-01-01T10:00:00Z",
    "version": "1.0.0",
    "uptime_seconds": 3600,
    "services": {
      "api": "running",
      "collector": "running",
      "storage": "healthy"
    }
  }
}
```

#### GET /api/v1/status
**Description**: Get detailed system status

**Example Request**:
```bash
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/status"
```

**Example Response**:
```json
{
  "success": true,
  "data": {
    "status": "operational",
    "timestamp": "2023-01-01T10:00:00Z",
    "stats": {
      "reports_collected": 150,
      "systems_monitored": 10,
      "api_requests_today": 245,
      "active_alerts": 0
    },
    "health_checks": {
      "database": "healthy",
      "storage": "healthy",
      "network": "healthy"
    }
  }
}
```

### Users & Permissions

#### GET /api/v1/users (Admin only)
**Description**: List system users (admin access required)

**Example Request**:
```bash
curl -H "X-API-Key: admin-api-key" \
     "https://api.example.com/api/v1/users"
```

**Example Response**:
```json
{
  "success": true,
  "data": [
    {
      "username": "admin",
      "role": "admin",
      "last_login": "2023-01-01T09:30:00Z",
      "active": true
    },
    {
      "username": "report_viewer",
      "role": "report_viewer",
      "last_login": "2023-01-01T08:45:00Z",
      "active": true
    }
  ],
  "timestamp": "2023-01-01T10:00:00Z"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Anonymous requests**: 10 requests per minute
- **Authenticated requests**: 100 requests per minute
- **Admin requests**: 1000 requests per minute

Rate limit information is included in response headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1672531200
```

## Error Codes

### Common Error Codes
- `CONFIG_VALIDATION_ERROR`: Configuration validation failed
- `REPORT_NOT_FOUND`: Requested report does not exist
- `PERMISSION_DENIED`: Insufficient permissions for the requested action
- `UNAUTHORIZED`: Authentication failed or missing
- `RATE_LIMIT_EXCEEDED`: Rate limit has been exceeded
- `INTERNAL_ERROR`: Internal server error occurred

### HTTP Status Code to Error Mapping
```
400 - BAD_REQUEST, CONFIG_VALIDATION_ERROR
401 - UNAUTHORIZED
403 - PERMISSION_DENIED
404 - REPORT_NOT_FOUND
429 - RATE_LIMIT_EXCEEDED
500 - INTERNAL_ERROR
```

## SDK Examples

### cURL
```bash
# Get reports
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/reports?type=system&limit=5"

# Get system details
curl -H "X-API-Key: your-api-key" \
     "https://api.example.com/api/v1/systems/server1.example.com"

# Update configuration
curl -X PUT \
     -H "X-API-Key: admin-api-key" \
     -H "Content-Type: application/json" \
     -d '{"general": {"retention_days": 60}}' \
     "https://api.example.com/api/v1/config"
```

### Python
```python
import requests

class ReportsAPIClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'X-API-Key': api_key,
            'Content-Type': 'application/json'
        }
    
    def get_reports(self, report_type=None, limit=20):
        params = {'limit': limit}
        if report_type:
            params['type'] = report_type
        
        response = requests.get(
            f"{self.base_url}/api/v1/reports",
            headers=self.headers,
            params=params
        )
        return response.json()
    
    def get_report(self, report_id):
        response = requests.get(
            f"{self.base_url}/api/v1/reports/{report_id}",
            headers=self.headers
        )
        return response.json()
    
    def get_system_status(self):
        response = requests.get(
            f"{self.base_url}/api/v1/status",
            headers=self.headers
        )
        return response.json()

# Usage
client = ReportsAPIClient('https://api.example.com', 'your-api-key')
status = client.get_system_status()
reports = client.get_reports(report_type='system')
```

### JavaScript
```javascript
class ReportsAPI {
  constructor(baseURL, apiKey) {
    this.baseURL = baseURL.replace(/\/$/, '');
    this.headers = {
      'X-API-Key': apiKey,
      'Content-Type': 'application/json'
    };
  }
  
  async getReports(reportType = null, limit = 20) {
    const params = new URLSearchParams({ limit });
    if (reportType) params.append('type', reportType);
    
    const response = await fetch(`${this.baseURL}/api/v1/reports?${params}`, {
      headers: this.headers
    });
    return await response.json();
  }
  
  async getReport(reportId) {
    const response = await fetch(`${this.baseURL}/api/v1/reports/${reportId}`, {
      headers: this.headers
    });
    return await response.json();
  }
  
  async getSystemStatus() {
    const response = await fetch(`${this.baseURL}/api/v1/status`, {
      headers: this.headers
    });
    return await response.json();
  }
}

// Usage
const client = new ReportsAPI('https://api.example.com', 'your-api-key');
const status = await client.getSystemStatus();
const reports = await client.getReports('system', 5);
```

## Webhook Integration

The system can send webhook notifications for specific events:

### Webhook Payload Format
```json
{
  "event": "report_collected",
  "timestamp": "2023-01-01T10:00:00Z",
  "data": {
    "report_id": "report123",
    "hostname": "server1.example.com",
    "type": "system",
    "size_bytes": 1500
  }
}
```

### Signature Verification
Webhook payloads include a signature in the `X-Signature` header:
```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected_signature = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected_signature)
```

## Testing the API

### Health Check
```bash
curl -I https://api.example.com/api/v1/health
```

### Authentication Test
```bash
curl -H "X-API-Key: invalid-key" \
     "https://api.example.com/api/v1/reports" 2>&1 | grep "401"
```

### Rate Limiting Test
```bash
for i in {1..101}; do
  curl -H "X-API-Key: your-api-key" \
       "https://api.example.com/api/v1/reports" -o /dev/null -s -w "%{http_code}\n"
done
```

For more information about API usage, authentication, and integration, see:
- [Configuration Guide](configuration.md)
- [Security Documentation](security.md)
- [Integration Guide](integrations.md)