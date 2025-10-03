# Scalable Architecture for Enterprise Reporting System

## Overview

This document outlines the scalable architecture design for the Enterprise Reporting System, designed to handle large-scale deployments with thousands of endpoints while maintaining performance and reliability.

## Architecture Principles

### 1. Microservices Design
- **Decoupled Components**: Each system function operates as an independent service
- **API-First Approach**: All communication happens via well-defined APIs
- **Stateless Services**: Services don't store local state when possible

### 2. Horizontal Scaling
- **Load Distribution**: Distribute workloads across multiple nodes
- **Elastic Scaling**: Automatically scale based on demand
- **Distributed Processing**: Parallel processing of reports across multiple nodes

### 3. Resilience Patterns
- **Circuit Breakers**: Prevent cascading failures
- **Retry Mechanisms**: Handle temporary failures gracefully
- **Health Checks**: Monitor service health continuously

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Load Balancer                                     │
└─────────────────┬───────────────────────────────────────────────────────────┘
                  │
┌─────────────────▼─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│         API Gateway               │ │    Web UI       │ │   Monitoring    │
│                                 │ │                 │ │                 │
├─────────────────┬───────────────┤ └─────────────────┘ └─────────────────┘
│                 │               │
│   ┌─────────────▼─────────────┐ │ ┌─────────────────────────────────────────┐
│   │      Authentication       │ │ │              Data Storage               │
│   │        Service            │ │ │                                         │
│   └─────────────┬─────────────┘ │ │ ┌─────────────┐ ┌─────────────────────┐ │
└─────────────────┼───────────────┘ │ │   Reports   │ │     Audit Logs      │ │
                  │                 │ │   Storage   │ │       Storage       │ │
                  │                 │ └─────────────┘ └─────────────────────┘ │
┌─────────────────▼─────────────────┤                                       │
│          Report Collection        │ ┌─────────────────────────────────────┐ │
│             Service               │ │           Cache Layer               │ │
├─────────────────┬─────────────────┤ │                                     │ │
│                 │                 │ │ ┌─────────────┐ ┌─────────────────┐ │ │
│   ┌─────────────▼─────────────┐   │ │ │   Redis     │ │   CDN for UI    │ │ │
│   │   Remote Collection       │   │ │ │   Cache     │ │    Assets       │ │ │
│   │        Workers            │   │ │ └─────────────┘ └─────────────────┘ │ │
│   └───────────────────────────┘   │ └─────────────────────────────────────┘ │
│                 │                 │                                         │
│   ┌─────────────▼─────────────┐   │                                         │
│   │   Local Collection        │   │                                         │
│   │        Workers            │   │                                         │
│   └───────────────────────────┘   │                                         │
└───────────────────────────────────┘ └─────────────────────────────────────────┘
```

## Component Details

### 1. API Gateway Layer
Manages incoming requests and routes to appropriate services:

```yaml
# Example Kubernetes deployment for API Gateway
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api-gateway
  template:
    metadata:
      labels:
        app: api-gateway
    spec:
      containers:
      - name: gateway
        image: nginx:latest
        ports:
        - containerPort: 80
        volumeMounts:
        - name: nginx-config
          mountPath: /etc/nginx/nginx.conf
          subPath: nginx.conf
      volumes:
      - name: nginx-config
        configMap:
          name: api-gateway-config
---
apiVersion: v1
kind: Service
metadata:
  name: api-gateway-service
spec:
  selector:
    app: api-gateway
  ports:
  - port: 80
    targetPort: 80
  type: LoadBalancer
```

### 2. Authentication Service
Handles user authentication and session management:

```python
# auth_service.py - Distributed authentication service
import asyncio
import aioredis
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import jwt
from datetime import datetime, timedelta
from typing import Optional
import os

app = FastAPI(title="Authentication Service")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Redis connection for distributed session storage
redis_pool = None

async def get_redis_pool():
    global redis_pool
    if redis_pool is None:
        redis_pool = aioredis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379"),
            encoding="utf-8",
            decode_responses=True
        )
    return redis_pool

@app.on_event("startup")
async def startup_event():
    await get_redis_pool()

@app.post("/auth/login")
async def login(username: str, password: str):
    # Verify credentials (implement with your user management system)
    if verify_credentials(username, password):
        # Generate JWT token
        token = jwt.encode({
            "sub": username,
            "exp": datetime.utcnow() + timedelta(hours=24),
            "iat": datetime.utcnow()
        }, os.getenv("JWT_SECRET"), algorithm="HS256")
        
        # Store session in Redis with expiration
        redis = await get_redis_pool()
        await redis.setex(f"session:{token}", 86400, username)  # 24 hours
        
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/auth/logout")
async def logout(token: str):
    redis = await get_redis_pool()
    await redis.delete(f"session:{token}")
    return {"message": "Successfully logged out"}

def verify_credentials(username: str, password: str) -> bool:
    # Implement actual credential verification
    # This could be connecting to your user management system
    return True  # Placeholder

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

### 3. Report Collection Service
Handles distributed collection of reports:

```python
# collection_service.py - Distributed collection service
import asyncio
import aioredis
import aiohttp
from celery import Celery
from datetime import datetime
import json
import logging

# Celery configuration for distributed task queue
celery_app = Celery('reports_collection')
celery_app.conf.update(
    broker_url=os.getenv('REDIS_URL', 'redis://localhost:6379'),
    result_backend=os.getenv('REDIS_URL', 'redis://localhost:6379'),
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

@celery_app.task
def collect_system_report(hostname: str, config: dict):
    """Collect system report from a specific host"""
    try:
        # Implement collection logic here
        # This would typically SSH to the host and run collection scripts
        import subprocess
        result = subprocess.run(['ssh', f'user@{hostname}', 'uname -a'], 
                              capture_output=True, text=True, timeout=30)
        return {
            'hostname': hostname,
            'timestamp': datetime.utcnow().isoformat(),
            'data': result.stdout,
            'status': 'success' if result.returncode == 0 else 'failed'
        }
    except Exception as e:
        logging.error(f"Collection failed for {hostname}: {e}")
        return {
            'hostname': hostname,
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e),
            'status': 'failed'
        }

@celery_app.task
def process_collected_report(report_data: dict):
    """Process and store collected report"""
    # Store in appropriate backend
    # This could be sending to Elasticsearch, S3, or local files
    pass

# Worker startup script
async def start_collection_workers():
    """Start distributed collection workers"""
    # This would typically be run in a separate process
    pass
```

### 4. Data Storage Design

#### For Reports:
```sql
-- PostgreSQL partitioned table for reports (for large deployments)
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) PARTITION BY RANGE (created_at);

-- Create monthly partitions
CREATE TABLE reports_2023_01 PARTITION OF reports
    FOR VALUES FROM ('2023-01-01') TO ('2023-02-01');
    
CREATE TABLE reports_2023_02 PARTITION OF reports
    FOR VALUES FROM ('2023-02-01') TO ('2023-03-01');
    
-- Indexes for common queries
CREATE INDEX idx_reports_hostname_created_at ON reports (hostname, created_at);
CREATE INDEX idx_reports_type_created_at ON reports (report_type, created_at);
CREATE INDEX idx_reports_created_at ON reports (created_at);
```

#### For Audit Logs:
```sql
-- Separate partitioned table for audit logs
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) PARTITION BY RANGE (created_at);
```

### 5. Docker Compose for Development
```yaml
# docker-compose.scalable.yml
version: '3.8'

services:
  # Redis for session storage and task queue
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes

  # PostgreSQL for data storage
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: reports
      POSTGRES_USER: reports_user
      POSTGRES_PASSWORD: reports_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql

  # API Gateway
  nginx:
    image: nginx:latest
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - api-auth
      - api-collection

  # Authentication Service
  api-auth:
    build:
      context: .
      dockerfile: Dockerfile.auth
    environment:
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=your-super-secret-jwt-key
    depends_on:
      - redis

  # Collection Service
  api-collection:
    build:
      context: .
      dockerfile: Dockerfile.collection
    environment:
      - REDIS_URL=redis://redis:6379
      - POSTGRES_URL=postgresql://reports_user:reports_password@postgres:5432/reports
    depends_on:
      - redis
      - postgres

  # Celery Workers
  celery-worker:
    build:
      context: .
      dockerfile: Dockerfile.collection
    command: celery -A collection_service worker --loglevel=info
    environment:
      - REDIS_URL=redis://redis:6379
      - POSTGRES_URL=postgresql://reports_user:reports_password@postgres:5432/reports
    depends_on:
      - redis
      - postgres

  # Celery Beat (for scheduled tasks)
  celery-beat:
    build:
      context: .
      dockerfile: Dockerfile.collection
    command: celery -A collection_service beat --loglevel=info
    environment:
      - REDIS_URL=redis://redis:6379
      - POSTGRES_URL=postgresql://reports_user:reports_password@postgres:5432/reports
    depends_on:
      - redis
      - postgres

volumes:
  redis_data:
  postgres_data:
```

### 6. Kubernetes Deployment
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reports-api
  labels:
    app: reports-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: reports-api
  template:
    metadata:
      labels:
        app: reports-api
    spec:
      containers:
      - name: api
        image: enterprise-reports/api:latest
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: reports-api-service
spec:
  selector:
    app: reports-api
  ports:
  - port: 80
    targetPort: 8000
  type: ClusterIP
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: reports-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: reports-api
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Performance Optimization Strategies

### 1. Caching Layer
```python
# cache_manager.py
import aioredis
import json
from typing import Any, Optional

class CacheManager:
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis = None

    async def connect(self):
        self.redis = aioredis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True
        )

    async def get(self, key: str) -> Optional[Any]:
        if not self.redis:
            await self.connect()
        
        value = await self.redis.get(key)
        if value:
            return json.loads(value)
        return None

    async def set(self, key: str, value: Any, expire: int = 3600):
        if not self.redis:
            await self.connect()
        
        await self.redis.setex(key, expire, json.dumps(value))

    async def delete(self, key: str):
        if not self.redis:
            await self.connect()
        
        await self.redis.delete(key)
```

### 2. Database Connection Pooling
```python
# db_manager.py
import asyncpg
from typing import Optional

class DatabaseManager:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool: Optional[asyncpg.Pool] = None

    async def create_pool(self):
        self.pool = await asyncpg.create_pool(
            self.dsn,
            min_size=10,
            max_size=30,
            command_timeout=60
        )

    async def get_connection(self):
        if not self.pool:
            await self.create_pool()
        return self.pool.acquire()

    async def execute_query(self, query: str, *args):
        async with self.pool.acquire() as conn:
            return await conn.fetch(query, *args)
```

### 3. Asynchronous Processing
```python
# async_collector.py
import asyncio
import aiohttp
from typing import List, Dict
import time

class AsyncCollector:
    def __init__(self, max_concurrent: int = 10):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def collect_from_host(self, host_config: Dict) -> Dict:
        async with self.semaphore:  # Limit concurrent connections
            try:
                async with self.session.get(
                    f"http://{host_config['host']}/api/health",
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    data = await response.json()
                    return {
                        'host': host_config['host'],
                        'status': 'success',
                        'data': data,
                        'timestamp': time.time()
                    }
            except Exception as e:
                return {
                    'host': host_config['host'],
                    'status': 'failed',
                    'error': str(e),
                    'timestamp': time.time()
                }

    async def collect_batch(self, hosts: List[Dict]) -> List[Dict]:
        tasks = [self.collect_from_host(host) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]
```

## Auto-Scaling Configuration

### Horizontal Pod Autoscaler (Kubernetes)
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: reports-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: reports-api
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

### Cluster Autoscaler Configuration
```yaml
# cluster-autoscaler-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cluster-autoscaler-status
  namespace: kube-system
data:
  status: "ok"
```

## Monitoring and Health Checks

### Health Check Endpoints
```python
# health_checks.py
from fastapi import FastAPI
import asyncio
import asyncpg
import aioredis

app = FastAPI()

@app.get("/health")
async def health_check():
    checks = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {}
    }
    
    # Check database connectivity
    try:
        # Test DB connection
        checks["checks"]["database"] = "ok"
    except Exception as e:
        checks["checks"]["database"] = f"error: {str(e)}"
        checks["status"] = "unhealthy"
    
    # Check Redis connectivity
    try:
        # Test Redis connection
        checks["checks"]["redis"] = "ok"
    except Exception as e:
        checks["checks"]["redis"] = f"error: {str(e)}"
        checks["status"] = "unhealthy"
    
    # Check storage availability
    try:
        # Test storage
        checks["checks"]["storage"] = "ok"
    except Exception as e:
        checks["checks"]["storage"] = f"error: {str(e)}"
        checks["status"] = "unhealthy"
    
    return checks
```

## Deployment Strategies

### Blue-Green Deployment
1. Deploy new version to "green" environment
2. Run health checks and validation tests
3. Switch traffic from "blue" to "green"
4. Monitor for issues
5. If issues arise, switch traffic back immediately

### Canary Deployment
1. Deploy new version to small subset of servers (e.g., 10%)
2. Monitor metrics and error rates
3. Gradually increase traffic to new version
4. Roll back if issues are detected

## Performance Tuning Recommendations

### For Large Deployments (>1000 hosts):
- Use multiple collection workers spread across different availability zones
- Implement database sharding based on hostname or geographic regions
- Use message queues (like RabbitMQ or Kafka) for high-throughput scenarios
- Deploy CDN for static assets and cached reports
- Implement read replicas for database queries

### For Very Large Deployments (>10000 hosts):
- Use stream processing (Apache Kafka + KStreams or Apache Flink)
- Implement data lakes for historical analysis
- Use specialized time-series databases (InfluxDB, TimescaleDB)
- Consider using Apache Spark for analytics
- Implement advanced caching with multiple tiers

This architecture provides a solid foundation for scaling the Enterprise Reporting System to handle thousands of endpoints while maintaining reliability, performance, and security.