"""
Performance Monitoring and Profiling System for Enterprise Reporting System
"""

import asyncio
import time
import logging
import psutil
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json
import gc
import tracemalloc
import cProfile
import pstats
from io import StringIO
import functools
from collections import defaultdict, deque
import sqlite3
from contextlib import contextmanager
import warnings
import sys
import os
from concurrent.futures import ThreadPoolExecutor
import objgraph
from pympler import tracker, summary, muppy
from memory_profiler import profile as memory_profile
import line_profiler
import yappi
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, Summary
import redis
import aioredis
from sqlalchemy import create_engine
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

@dataclass
class PerformanceConfig:
    """Performance monitoring configuration"""
    # General settings
    enable_monitoring: bool = True
    monitoring_interval_seconds: int = 60
    enable_profiling: bool = True
    profiling_sample_rate: float = 0.1  # 10% sampling
    
    # Resource monitoring
    enable_resource_monitoring: bool = True
    resource_monitoring_interval_seconds: int = 10
    enable_cpu_monitoring: bool = True
    enable_memory_monitoring: bool = True
    enable_disk_monitoring: bool = True
    enable_network_monitoring: bool = True
    enable_process_monitoring: bool = True
    
    # Performance profiling
    enable_function_profiling: bool = True
    enable_line_profiling: bool = True
    enable_memory_profiling: bool = True
    enable_object_profiling: bool = True
    enable_call_stack_profiling: bool = True
    
    # Database monitoring
    enable_database_monitoring: bool = True
    database_monitoring_interval_seconds: int = 30
    enable_query_profiling: bool = True
    slow_query_threshold_ms: int = 1000
    enable_connection_pool_monitoring: bool = True
    
    # Web monitoring
    enable_web_monitoring: bool = True
    web_monitoring_interval_seconds: int = 15
    enable_request_profiling: bool = True
    slow_request_threshold_ms: int = 5000
    enable_response_time_monitoring: bool = True
    
    # Alerting
    enable_performance_alerting: bool = True
    alert_thresholds: Dict[str, Any] = None
    enable_slack_alerting: bool = False
    slack_webhook_url: Optional[str] = None
    enable_email_alerting: bool = False
    email_smtp_server: Optional[str] = None
    
    # Storage
    enable_local_storage: bool = True
    storage_path: str = "/tmp/performance_monitoring.db"
    enable_remote_storage: bool = False
    remote_storage_url: Optional[str] = None
    storage_retention_days: int = 30
    
    # Metrics export
    enable_prometheus_export: bool = True
    prometheus_port: int = 9091
    enable_graphite_export: bool = False
    graphite_host: Optional[str] = None
    enable_influxdb_export: bool = False
    influxdb_url: Optional[str] = None
    
    # Tracing
    enable_distributed_tracing: bool = True
    tracing_provider: str = "opentelemetry"  # opentelemetry, jaeger, zipkin
    enable_span_sampling: bool = True
    span_sampling_rate: float = 0.1  # 10% sampling
    
    def __post_init__(self):
        if self.alert_thresholds is None:
            self.alert_thresholds = {
                "cpu_usage_percent": 80.0,
                "memory_usage_percent": 85.0,
                "disk_usage_percent": 90.0,
                "response_time_ms": 5000,
                "error_rate_percent": 5.0,
                "garbage_collection_frequency": 100,  # GCs per hour
                "memory_leak_threshold_mb": 100,  # 100MB memory leak threshold
                "slow_queries_per_minute": 10,
                "slow_requests_per_minute": 5
            }

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_rss_mb: float
    memory_vms_mb: float
    disk_usage_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    process_count: int
    thread_count: int
    open_file_count: int
    garbage_collection_count: int
    garbage_collection_time_ms: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class ProfilingResult:
    """Function profiling result"""
    function_name: str
    file_name: str
    line_number: int
    call_count: int
    total_time_ms: float
    cumulative_time_ms: float
    average_time_ms: float
    memory_delta_mb: float
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

class PerformanceMonitor:
    """Main performance monitoring system"""
    
    def __init__(self, config: PerformanceConfig):
        self.config = config
        self.is_running = False
        self.monitoring_tasks = set()
        self.metrics_registry = CollectorRegistry()
        self.metrics = {}
        self.profiling_results = deque(maxlen=1000)
        self.alert_conditions = {}
        self.alert_history = {}
        
        # Initialize metrics
        self._initialize_metrics()
        
        # Initialize storage
        self._initialize_storage()
        
        # Initialize profiling tools
        self._initialize_profiling_tools()
        
        logger.info("Performance monitoring system initialized")
    
    def _initialize_metrics(self):
        """Initialize Prometheus metrics"""
        if not self.config.enable_prometheus_export:
            return
        
        try:
            # System metrics
            self.metrics['cpu_usage_percent'] = Gauge(
                'system_cpu_usage_percent', 
                'CPU usage percentage',
                registry=self.metrics_registry
            )
            
            self.metrics['memory_usage_percent'] = Gauge(
                'system_memory_usage_percent', 
                'Memory usage percentage',
                registry=self.metrics_registry
            )
            
            self.metrics['disk_usage_percent'] = Gauge(
                'system_disk_usage_percent', 
                'Disk usage percentage',
                registry=self.metrics_registry
            )
            
            self.metrics['network_bytes_sent'] = Counter(
                'system_network_bytes_sent_total', 
                'Total network bytes sent',
                registry=self.metrics_registry
            )
            
            self.metrics['network_bytes_recv'] = Counter(
                'system_network_bytes_received_total', 
                'Total network bytes received',
                registry=self.metrics_registry
            )
            
            # Process metrics
            self.metrics['process_count'] = Gauge(
                'system_process_count', 
                'Number of running processes',
                registry=self.metrics_registry
            )
            
            self.metrics['thread_count'] = Gauge(
                'system_thread_count', 
                'Number of active threads',
                registry=self.metrics_registry
            )
            
            # Performance metrics
            self.metrics['response_time_seconds'] = Histogram(
                'http_request_duration_seconds', 
                'HTTP request duration in seconds',
                ['method', 'endpoint', 'status_code'],
                registry=self.metrics_registry
            )
            
            self.metrics['database_query_duration_seconds'] = Histogram(
                'database_query_duration_seconds', 
                'Database query duration in seconds',
                ['query_type', 'table_name'],
                registry=self.metrics_registry
            )
            
            self.metrics['function_execution_duration_seconds'] = Histogram(
                'function_execution_duration_seconds', 
                'Function execution duration in seconds',
                ['function_name', 'module_name'],
                registry=self.metrics_registry
            )
            
            logger.info("Performance metrics initialized")
            
        except Exception as e:
            logger.error(f"Error initializing metrics: {e}")
    
    def _initialize_storage(self):
        """Initialize storage for performance data"""
        try:
            if self.config.enable_local_storage:
                # Create SQLite database for local storage
                self.db_connection = sqlite3.connect(
                    self.config.storage_path,
                    check_same_thread=False
                )
                
                # Create tables
                self.db_connection.execute('''
                    CREATE TABLE IF NOT EXISTS performance_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME NOT NULL,
                        cpu_percent REAL,
                        memory_percent REAL,
                        memory_rss_mb REAL,
                        memory_vms_mb REAL,
                        disk_usage_percent REAL,
                        network_bytes_sent INTEGER,
                        network_bytes_recv INTEGER,
                        process_count INTEGER,
                        thread_count INTEGER,
                        open_file_count INTEGER,
                        garbage_collection_count INTEGER,
                        garbage_collection_time_ms REAL
                    )
                ''')
                
                self.db_connection.execute('''
                    CREATE TABLE IF NOT EXISTS profiling_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME NOT NULL,
                        function_name TEXT,
                        file_name TEXT,
                        line_number INTEGER,
                        call_count INTEGER,
                        total_time_ms REAL,
                        cumulative_time_ms REAL,
                        average_time_ms REAL,
                        memory_delta_mb REAL
                    )
                ''')
                
                self.db_connection.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME NOT NULL,
                        alert_type TEXT,
                        severity TEXT,
                        message TEXT,
                        resolved BOOLEAN DEFAULT FALSE,
                        resolved_at DATETIME
                    )
                ''')
                
                self.db_connection.commit()
                logger.info("Local storage initialized")
            
            # Initialize Redis for distributed storage if configured
            if self.config.enable_remote_storage and self.config.remote_storage_url:
                try:
                    self.redis_client = aioredis.from_url(self.config.remote_storage_url)
                    logger.info("Remote storage (Redis) initialized")
                except Exception as e:
                    logger.warning(f"Failed to initialize Redis storage: {e}")
                    self.redis_client = None
            
        except Exception as e:
            logger.error(f"Error initializing storage: {e}")
    
    def _initialize_profiling_tools(self):
        """Initialize profiling tools"""
        try:
            # Initialize memory profiler
            if self.config.enable_memory_profiling:
                self.memory_tracker = tracker.SummaryTracker()
                logger.info("Memory profiler initialized")
            
            # Initialize object profiler
            if self.config.enable_object_profiling:
                logger.info("Object profiler initialized")
            
            # Initialize call stack profiler
            if self.config.enable_call_stack_profiling:
                yappi.set_clock_type("wall")
                logger.info("Call stack profiler initialized")
            
        except Exception as e:
            logger.error(f"Error initializing profiling tools: {e}")
    
    async def start_monitoring(self):
        """Start performance monitoring"""
        try:
            if not self.config.enable_monitoring:
                logger.info("Performance monitoring is disabled")
                return
            
            self.is_running = True
            
            # Start background monitoring tasks
            self._start_monitoring_tasks()
            
            logger.info("Performance monitoring started")
            
        except Exception as e:
            logger.error(f"Error starting performance monitoring: {e}")
            raise
    
    async def stop_monitoring(self):
        """Stop performance monitoring"""
        try:
            self.is_running = False
            
            # Stop monitoring tasks
            await self._stop_monitoring_tasks()
            
            # Close database connection
            if hasattr(self, 'db_connection') and self.db_connection:
                self.db_connection.close()
            
            # Close Redis connection
            if hasattr(self, 'redis_client') and self.redis_client:
                await self.redis_client.close()
            
            logger.info("Performance monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping performance monitoring: {e}")
    
    def _start_monitoring_tasks(self):
        """Start background monitoring tasks"""
        # Start system resource monitoring
        if self.config.enable_resource_monitoring:
            resource_task = asyncio.create_task(self._resource_monitoring_task())
            self.monitoring_tasks.add(resource_task)
            resource_task.add_done_callback(self.monitoring_tasks.discard)
        
        # Start database monitoring
        if self.config.enable_database_monitoring:
            database_task = asyncio.create_task(self._database_monitoring_task())
            self.monitoring_tasks.add(database_task)
            database_task.add_done_callback(self.monitoring_tasks.discard)
        
        # Start web monitoring
        if self.config.enable_web_monitoring:
            web_task = asyncio.create_task(self._web_monitoring_task())
            self.monitoring_tasks.add(web_task)
            web_task.add_done_callback(self.monitoring_tasks.discard)
        
        # Start alert monitoring
        if self.config.enable_performance_alerting:
            alert_task = asyncio.create_task(self._alert_monitoring_task())
            self.monitoring_tasks.add(alert_task)
            alert_task.add_done_callback(self.monitoring_tasks.discard)
        
        # Start data cleanup task
        cleanup_task = asyncio.create_task(self._cleanup_task())
        self.monitoring_tasks.add(cleanup_task)
        cleanup_task.add_done_callback(self.monitoring_tasks.discard)
    
    async def _stop_monitoring_tasks(self):
        """Stop background monitoring tasks"""
        for task in self.monitoring_tasks:
            task.cancel()
        
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
    
    async def _resource_monitoring_task(self):
        """Background task for system resource monitoring"""
        try:
            while self.is_running:
                try:
                    # Collect system metrics
                    metrics = await self._collect_system_metrics()
                    
                    # Store metrics
                    await self._store_metrics(metrics)
                    
                    # Update Prometheus metrics
                    self._update_prometheus_metrics(metrics)
                    
                    # Check alert conditions
                    await self._check_alert_conditions(metrics)
                    
                    # Wait for next monitoring interval
                    await asyncio.sleep(self.config.resource_monitoring_interval_seconds)
                    
                except asyncio.CancelledError:
                    logger.info("Resource monitoring task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in resource monitoring task: {e}")
                    await asyncio.sleep(60)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Fatal error in resource monitoring task: {e}")
    
    async def _database_monitoring_task(self):
        """Background task for database monitoring"""
        try:
            while self.is_running:
                try:
                    # Collect database metrics (placeholder)
                    db_metrics = await self._collect_database_metrics()
                    
                    # Store database metrics
                    await self._store_database_metrics(db_metrics)
                    
                    # Check for slow queries
                    await self._check_slow_queries()
                    
                    # Wait for next monitoring interval
                    await asyncio.sleep(self.config.database_monitoring_interval_seconds)
                    
                except asyncio.CancelledError:
                    logger.info("Database monitoring task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in database monitoring task: {e}")
                    await asyncio.sleep(60)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Fatal error in database monitoring task: {e}")
    
    async def _web_monitoring_task(self):
        """Background task for web monitoring"""
        try:
            while self.is_running:
                try:
                    # Collect web metrics (placeholder)
                    web_metrics = await self._collect_web_metrics()
                    
                    # Store web metrics
                    await self._store_web_metrics(web_metrics)
                    
                    # Check for slow requests
                    await self._check_slow_requests()
                    
                    # Wait for next monitoring interval
                    await asyncio.sleep(self.config.web_monitoring_interval_seconds)
                    
                except asyncio.CancelledError:
                    logger.info("Web monitoring task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in web monitoring task: {e}")
                    await asyncio.sleep(60)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Fatal error in web monitoring task: {e}")
    
    async def _alert_monitoring_task(self):
        """Background task for alert monitoring"""
        try:
            while self.is_running:
                try:
                    # Check alert conditions
                    await self._evaluate_alert_conditions()
                    
                    # Send pending alerts
                    await self._send_pending_alerts()
                    
                    # Wait for next monitoring interval
                    await asyncio.sleep(30)  # Check alerts every 30 seconds
                    
                except asyncio.CancelledError:
                    logger.info("Alert monitoring task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in alert monitoring task: {e}")
                    await asyncio.sleep(60)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Fatal error in alert monitoring task: {e}")
    
    async def _cleanup_task(self):
        """Background task for data cleanup"""
        try:
            while self.is_running:
                try:
                    # Clean up old data
                    await self._cleanup_old_data()
                    
                    # Wait for next cleanup interval (1 hour)
                    await asyncio.sleep(3600)
                    
                except asyncio.CancelledError:
                    logger.info("Cleanup task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in cleanup task: {e}")
                    await asyncio.sleep(3600)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Fatal error in cleanup task: {e}")
    
    async def _collect_system_metrics(self) -> PerformanceMetrics:
        """Collect system resource metrics"""
        try:
            # Get process info
            current_process = psutil.Process()
            
            # Collect metrics
            cpu_percent = current_process.cpu_percent()
            memory_info = current_process.memory_info()
            disk_usage = psutil.disk_usage('/')
            network_io = psutil.net_io_counters()
            process_count = len(psutil.pids())
            
            # Get thread and file info
            thread_count = current_process.num_threads()
            try:
                open_file_count = current_process.num_fds()
            except (psutil.AccessDenied, AttributeError):
                open_file_count = 0
            
            # Get garbage collection info
            gc_stats = gc.get_stats()
            gc_count = sum(stat.get('collections', 0) for stat in gc_stats) if gc_stats else 0
            
            metrics = PerformanceMetrics(
                timestamp=datetime.utcnow(),
                cpu_percent=cpu_percent,
                memory_percent=current_process.memory_percent(),
                memory_rss_mb=memory_info.rss / 1024 / 1024,
                memory_vms_mb=memory_info.vms / 1024 / 1024,
                disk_usage_percent=(disk_usage.used / disk_usage.total) * 100,
                network_bytes_sent=network_io.bytes_sent,
                network_bytes_recv=network_io.bytes_recv,
                process_count=process_count,
                thread_count=thread_count,
                open_file_count=open_file_count,
                garbage_collection_count=gc_count,
                garbage_collection_time_ms=0.0  # Placeholder
            )
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            # Return default metrics
            return PerformanceMetrics(
                timestamp=datetime.utcnow(),
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_rss_mb=0.0,
                memory_vms_mb=0.0,
                disk_usage_percent=0.0,
                network_bytes_sent=0,
                network_bytes_recv=0,
                process_count=0,
                thread_count=0,
                open_file_count=0,
                garbage_collection_count=0,
                garbage_collection_time_ms=0.0
            )
    
    async def _collect_database_metrics(self) -> Dict[str, Any]:
        """Collect database metrics"""
        try:
            # Placeholder for database metrics collection
            # In a real implementation, this would connect to the database
            # and collect metrics like connection pool status, query performance, etc.
            
            return {
                'timestamp': datetime.utcnow(),
                'connection_pool_size': 0,
                'active_connections': 0,
                'idle_connections': 0,
                'max_connections': 0,
                'query_count': 0,
                'slow_query_count': 0,
                'average_query_time_ms': 0.0,
                'max_query_time_ms': 0.0
            }
            
        except Exception as e:
            logger.error(f"Error collecting database metrics: {e}")
            return {'error': str(e)}
    
    async def _collect_web_metrics(self) -> Dict[str, Any]:
        """Collect web metrics"""
        try:
            # Placeholder for web metrics collection
            # In a real implementation, this would collect metrics like
            # request rates, response times, error rates, etc.
            
            return {
                'timestamp': datetime.utcnow(),
                'request_count': 0,
                'error_count': 0,
                'average_response_time_ms': 0.0,
                'max_response_time_ms': 0.0,
                'active_connections': 0,
                'queued_requests': 0
            }
            
        except Exception as e:
            logger.error(f"Error collecting web metrics: {e}")
            return {'error': str(e)}
    
    async def _store_metrics(self, metrics: PerformanceMetrics):
        """Store performance metrics"""
        try:
            if self.config.enable_local_storage and hasattr(self, 'db_connection'):
                # Insert metrics into database
                self.db_connection.execute('''
                    INSERT INTO performance_metrics (
                        timestamp, cpu_percent, memory_percent, memory_rss_mb,
                        memory_vms_mb, disk_usage_percent, network_bytes_sent,
                        network_bytes_recv, process_count, thread_count,
                        open_file_count, garbage_collection_count,
                        garbage_collection_time_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.timestamp,
                    metrics.cpu_percent,
                    metrics.memory_percent,
                    metrics.memory_rss_mb,
                    metrics.memory_vms_mb,
                    metrics.disk_usage_percent,
                    metrics.network_bytes_sent,
                    metrics.network_bytes_recv,
                    metrics.process_count,
                    metrics.thread_count,
                    metrics.open_file_count,
                    metrics.garbage_collection_count,
                    metrics.garbage_collection_time_ms
                ))
                
                self.db_connection.commit()
            
            # Store in Redis if configured
            if self.config.enable_remote_storage and hasattr(self, 'redis_client'):
                try:
                    metrics_dict = metrics.to_dict()
                    await self.redis_client.lpush(
                        'performance_metrics',
                        json.dumps(metrics_dict, default=str)
                    )
                    # Trim list to prevent unbounded growth
                    await self.redis_client.ltrim('performance_metrics', 0, 1000)
                except Exception as e:
                    logger.debug(f"Error storing metrics in Redis: {e}")
            
        except Exception as e:
            logger.error(f"Error storing metrics: {e}")
    
    async def _store_database_metrics(self, db_metrics: Dict[str, Any]):
        """Store database metrics"""
        try:
            if self.config.enable_local_storage and hasattr(self, 'db_connection'):
                # Store database metrics (placeholder)
                pass
            
        except Exception as e:
            logger.error(f"Error storing database metrics: {e}")
    
    async def _store_web_metrics(self, web_metrics: Dict[str, Any]):
        """Store web metrics"""
        try:
            if self.config.enable_local_storage and hasattr(self, 'db_connection'):
                # Store web metrics (placeholder)
                pass
            
        except Exception as e:
            logger.error(f"Error storing web metrics: {e}")
    
    def _update_prometheus_metrics(self, metrics: PerformanceMetrics):
        """Update Prometheus metrics"""
        try:
            if not self.config.enable_prometheus_export:
                return
            
            # Update system metrics
            self.metrics['cpu_usage_percent'].set(metrics.cpu_percent)
            self.metrics['memory_usage_percent'].set(metrics.memory_percent)
            self.metrics['disk_usage_percent'].set(metrics.disk_usage_percent)
            
            # Update counters (only increment)
            # Note: These should be handled differently as they're cumulative
            # For now, we'll set them directly, but in reality you'd track deltas
            self.metrics['network_bytes_sent'].inc(0)  # Placeholder
            self.metrics['network_bytes_recv'].inc(0)  # Placeholder
            
            # Update process metrics
            self.metrics['process_count'].set(metrics.process_count)
            self.metrics['thread_count'].set(metrics.thread_count)
            
        except Exception as e:
            logger.error(f"Error updating Prometheus metrics: {e}")
    
    async def _check_alert_conditions(self, metrics: PerformanceMetrics):
        """Check performance alert conditions"""
        try:
            alert_conditions_triggered = []
            
            # Check CPU usage
            if metrics.cpu_percent > self.config.alert_thresholds['cpu_usage_percent']:
                alert_conditions_triggered.append({
                    'type': 'high_cpu_usage',
                    'severity': 'warning',
                    'message': f'CPU usage is {metrics.cpu_percent:.2f}%, exceeding threshold of {self.config.alert_thresholds["cpu_usage_percent"]}%'
                })
            
            # Check memory usage
            if metrics.memory_percent > self.config.alert_thresholds['memory_usage_percent']:
                alert_conditions_triggered.append({
                    'type': 'high_memory_usage',
                    'severity': 'warning',
                    'message': f'Memory usage is {metrics.memory_percent:.2f}%, exceeding threshold of {self.config.alert_thresholds["memory_usage_percent"]}%'
                })
            
            # Check disk usage
            if metrics.disk_usage_percent > self.config.alert_thresholds['disk_usage_percent']:
                alert_conditions_triggered.append({
                    'type': 'high_disk_usage',
                    'severity': 'warning',
                    'message': f'Disk usage is {metrics.disk_usage_percent:.2f}%, exceeding threshold of {self.config.alert_thresholds["disk_usage_percent"]}%'
                })
            
            # Store alert conditions
            for alert_condition in alert_conditions_triggered:
                self.alert_conditions[alert_condition['type']] = {
                    'condition': alert_condition,
                    'timestamp': datetime.utcnow(),
                    'resolved': False
                }
            
        except Exception as e:
            logger.error(f"Error checking alert conditions: {e}")
    
    async def _evaluate_alert_conditions(self):
        """Evaluate alert conditions and trigger alerts"""
        try:
            current_time = datetime.utcnow()
            
            for alert_type, alert_info in self.alert_conditions.items():
                if not alert_info['resolved']:
                    # Check if alert should be resolved
                    if await self._should_resolve_alert(alert_type, alert_info):
                        alert_info['resolved'] = True
                        alert_info['resolved_at'] = current_time
                        
                        # Store resolved alert
                        await self._store_alert({
                            **alert_info['condition'],
                            'resolved': True,
                            'resolved_at': current_time
                        })
                    else:
                        # Check if alert should be escalated
                        await self._check_alert_escalation(alert_type, alert_info)
        
        except Exception as e:
            logger.error(f"Error evaluating alert conditions: {e}")
    
    async def _should_resolve_alert(self, alert_type: str, alert_info: Dict[str, Any]) -> bool:
        """Check if an alert should be resolved"""
        try:
            # Get current metrics
            current_metrics = await self._collect_system_metrics()
            
            # Check based on alert type
            if alert_type == 'high_cpu_usage':
                return current_metrics.cpu_percent <= self.config.alert_thresholds['cpu_usage_percent'] * 0.9
            elif alert_type == 'high_memory_usage':
                return current_metrics.memory_percent <= self.config.alert_thresholds['memory_usage_percent'] * 0.9
            elif alert_type == 'high_disk_usage':
                return current_metrics.disk_usage_percent <= self.config.alert_thresholds['disk_usage_percent'] * 0.9
            else:
                # For other alert types, resolve after timeout
                alert_duration = datetime.utcnow() - alert_info['timestamp']
                return alert_duration.total_seconds() > 300  # Resolve after 5 minutes if not re-triggered
            
        except Exception as e:
            logger.error(f"Error checking alert resolution: {e}")
            return False
    
    async def _check_alert_escalation(self, alert_type: str, alert_info: Dict[str, Any]):
        """Check if an alert should be escalated"""
        try:
            # Check alert duration
            alert_duration = datetime.utcnow() - alert_info['timestamp']
            
            # Escalate critical alerts after 5 minutes
            if alert_duration.total_seconds() > 300:
                # Update alert severity
                alert_condition = alert_info['condition']
                if alert_condition['severity'] == 'warning':
                    alert_condition['severity'] = 'critical'
                    alert_condition['message'] = f"CRITICAL: {alert_condition['message']}"
                    
                    # Update alert in conditions
                    self.alert_conditions[alert_type]['condition'] = alert_condition
                    
                    logger.critical(f"Alert escalated: {alert_condition['message']}")
        
        except Exception as e:
            logger.error(f"Error checking alert escalation: {e}")
    
    async def _send_pending_alerts(self):
        """Send pending alerts"""
        try:
            # Get unresolved alerts
            unresolved_alerts = [
                alert_info for alert_info in self.alert_conditions.values()
                if not alert_info['resolved']
            ]
            
            # Send alerts (placeholder)
            for alert_info in unresolved_alerts:
                await self._send_alert(alert_info['condition'])
        
        except Exception as e:
            logger.error(f"Error sending pending alerts: {e}")
    
    async def _send_alert(self, alert_condition: Dict[str, Any]):
        """Send alert notification"""
        try:
            # Log alert
            logger.warning(f"PERFORMANCE ALERT [{alert_condition['severity'].upper()}]: {alert_condition['message']}")
            
            # Store alert
            await self._store_alert(alert_condition)
            
            # Send to external systems if configured
            if self.config.enable_slack_alerting and self.config.slack_webhook_url:
                await self._send_slack_alert(alert_condition)
            
            if self.config.enable_email_alerting and self.config.email_smtp_server:
                await self._send_email_alert(alert_condition)
        
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    async def _store_alert(self, alert_condition: Dict[str, Any]):
        """Store alert in database"""
        try:
            if self.config.enable_local_storage and hasattr(self, 'db_connection'):
                self.db_connection.execute('''
                    INSERT INTO alerts (
                        timestamp, alert_type, severity, message, resolved
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    alert_condition.get('timestamp', datetime.utcnow()),
                    alert_condition.get('type', 'unknown'),
                    alert_condition.get('severity', 'info'),
                    alert_condition.get('message', 'Unknown alert'),
                    alert_condition.get('resolved', False)
                ))
                
                self.db_connection.commit()
        
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
    
    async def _send_slack_alert(self, alert_condition: Dict[str, Any]):
        """Send alert to Slack"""
        try:
            # Placeholder for Slack integration
            # In a real implementation, this would send to Slack webhook
            pass
            
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
    
    async def _send_email_alert(self, alert_condition: Dict[str, Any]):
        """Send alert via email"""
        try:
            # Placeholder for email integration
            # In a real implementation, this would send email via SMTP
            pass
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
    
    async def _check_slow_queries(self):
        """Check for slow database queries"""
        try:
            # Placeholder for slow query detection
            # In a real implementation, this would monitor database query performance
            pass
            
        except Exception as e:
            logger.error(f"Error checking slow queries: {e}")
    
    async def _check_slow_requests(self):
        """Check for slow web requests"""
        try:
            # Placeholder for slow request detection
            # In a real implementation, this would monitor web request performance
            pass
            
        except Exception as e:
            logger.error(f"Error checking slow requests: {e}")
    
    async def _cleanup_old_data(self):
        """Clean up old performance data"""
        try:
            if self.config.enable_local_storage and hasattr(self, 'db_connection'):
                # Calculate cutoff date
                cutoff_date = datetime.utcnow() - timedelta(
                    days=self.config.storage_retention_days
                )
                
                # Delete old metrics
                self.db_connection.execute('''
                    DELETE FROM performance_metrics 
                    WHERE timestamp < ?
                ''', (cutoff_date,))
                
                # Delete old alerts
                self.db_connection.execute('''
                    DELETE FROM alerts 
                    WHERE timestamp < ?
                ''', (cutoff_date,))
                
                # Delete old profiling results
                self.db_connection.execute('''
                    DELETE FROM profiling_results 
                    WHERE timestamp < ?
                ''', (cutoff_date,))
                
                self.db_connection.commit()
                
                logger.info(f"Cleaned up performance data older than {self.config.storage_retention_days} days")
        
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get current system metrics"""
        try:
            metrics = asyncio.run(self._collect_system_metrics())
            return metrics.to_dict()
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return {'error': str(e)}
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        try:
            # Get recent metrics from database
            if self.config.enable_local_storage and hasattr(self, 'db_connection'):
                cursor = self.db_connection.execute('''
                    SELECT 
                        AVG(cpu_percent) as avg_cpu,
                        MAX(cpu_percent) as max_cpu,
                        AVG(memory_percent) as avg_memory,
                        MAX(memory_percent) as max_memory,
                        AVG(disk_usage_percent) as avg_disk,
                        MAX(disk_usage_percent) as max_disk
                    FROM performance_metrics 
                    WHERE timestamp > datetime('now', '-1 hour')
                ''')
                
                row = cursor.fetchone()
                if row:
                    return {
                        'time_period': 'last_hour',
                        'average_cpu_percent': row[0] or 0,
                        'max_cpu_percent': row[1] or 0,
                        'average_memory_percent': row[2] or 0,
                        'max_memory_percent': row[3] or 0,
                        'average_disk_percent': row[4] or 0,
                        'max_disk_percent': row[5] or 0,
                        'timestamp': datetime.utcnow().isoformat()
                    }
            
            return {'error': 'No data available'}
            
        except Exception as e:
            logger.error(f"Error getting performance summary: {e}")
            return {'error': str(e)}
    
    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        try:
            if self.config.enable_local_storage and hasattr(self, 'db_connection'):
                cursor = self.db_connection.execute('''
                    SELECT * FROM alerts 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                columns = [description[0] for description in cursor.description]
                alerts = []
                
                for row in cursor.fetchall():
                    alert = dict(zip(columns, row))
                    # Convert timestamp if it's a string
                    if isinstance(alert['timestamp'], str):
                        try:
                            alert['timestamp'] = datetime.fromisoformat(alert['timestamp'])
                        except ValueError:
                            pass
                    alerts.append(alert)
                
                return alerts
            
            return []
            
        except Exception as e:
            logger.error(f"Error getting alerts: {e}")
            return []
    
    def get_profiling_results(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent profiling results"""
        try:
            results = []
            for result in list(self.profiling_results)[-limit:]:
                results.append(result.to_dict())
            return results
            
        except Exception as e:
            logger.error(f"Error getting profiling results: {e}")
            return []

class Profiler:
    """Performance profiler with multiple profiling methods"""
    
    def __init__(self, performance_monitor: PerformanceMonitor):
        self.performance_monitor = performance_monitor
        self.profiler = None
        self.line_profiler = None
        self.memory_profiler = None
        self.call_stack_profiler = None
    
    def profile_function(self, func: Callable) -> Callable:
        """Decorator to profile a function"""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Check if profiling is enabled and should sample this call
            if (not self.performance_monitor.config.enable_profiling or
                not self._should_profile()):
                return func(*args, **kwargs)
            
            start_time = time.time()
            
            # Start profiling
            if self.performance_monitor.config.enable_function_profiling:
                pr = cProfile.Profile()
                pr.enable()
            else:
                pr = None
            
            # Start memory profiling if enabled
            memory_start = None
            if self.performance_monitor.config.enable_memory_profiling:
                tracemalloc.start()
                memory_start = tracemalloc.take_snapshot()
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                return result
                
            finally:
                # Stop profiling
                if pr:
                    pr.disable()
                
                # Stop memory profiling
                memory_delta = 0
                if memory_start:
                    memory_end = tracemalloc.take_snapshot()
                    memory_stats = memory_end.compare_to(memory_start, 'lineno')
                    if memory_stats:
                        memory_delta = sum(stat.size_diff for stat in memory_stats) / 1024 / 1024  # MB
                    tracemalloc.stop()
                
                # Calculate execution time
                execution_time = (time.time() - start_time) * 1000  # ms
                
                # Store profiling result
                profiling_result = ProfilingResult(
                    function_name=func.__name__,
                    file_name=func.__code__.co_filename,
                    line_number=func.__code__.co_firstlineno,
                    call_count=1,
                    total_time_ms=execution_time,
                    cumulative_time_ms=execution_time,
                    average_time_ms=execution_time,
                    memory_delta_mb=memory_delta,
                    timestamp=datetime.utcnow()
                )
                
                # Add to profiling results
                self.performance_monitor.profiling_results.append(profiling_result)
                
                # Store in database if enabled
                if (self.performance_monitor.config.enable_local_storage and
                    hasattr(self.performance_monitor, 'db_connection')):
                    try:
                        self.performance_monitor.db_connection.execute('''
                            INSERT INTO profiling_results (
                                timestamp, function_name, file_name, line_number,
                                call_count, total_time_ms, cumulative_time_ms,
                                average_time_ms, memory_delta_mb
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            profiling_result.timestamp,
                            profiling_result.function_name,
                            profiling_result.file_name,
                            profiling_result.line_number,
                            profiling_result.call_count,
                            profiling_result.total_time_ms,
                            profiling_result.cumulative_time_ms,
                            profiling_result.average_time_ms,
                            profiling_result.memory_delta_mb
                        ))
                        
                        self.performance_monitor.db_connection.commit()
                    except Exception as e:
                        logger.error(f"Error storing profiling result: {e}")
        
        return wrapper
    
    def _should_profile(self) -> bool:
        """Determine if this call should be profiled"""
        # Use sampling to reduce overhead
        return (
            self.performance_monitor.config.enable_profiling and
            time.time() % (1 / self.performance_monitor.config.profiling_sample_rate) < 1
        )
    
    @contextmanager
    def profile_block(self, block_name: str):
        """Context manager to profile a code block"""
        start_time = time.time()
        
        # Start profiling
        if self.performance_monitor.config.enable_function_profiling:
            pr = cProfile.Profile()
            pr.enable()
        else:
            pr = None
        
        # Start memory profiling if enabled
        memory_start = None
        if self.performance_monitor.config.enable_memory_profiling:
            tracemalloc.start()
            memory_start = tracemalloc.take_snapshot()
        
        try:
            yield
        finally:
            # Stop profiling
            if pr:
                pr.disable()
            
            # Stop memory profiling
            memory_delta = 0
            if memory_start:
                memory_end = tracemalloc.take_snapshot()
                memory_stats = memory_end.compare_to(memory_start, 'lineno')
                if memory_stats:
                    memory_delta = sum(stat.size_diff for stat in memory_stats) / 1024 / 1024  # MB
                tracemalloc.stop()
            
            # Calculate execution time
            execution_time = (time.time() - start_time) * 1000  # ms
            
            # Store profiling result
            profiling_result = ProfilingResult(
                function_name=block_name,
                file_name="<context>",
                line_number=0,
                call_count=1,
                total_time_ms=execution_time,
                cumulative_time_ms=execution_time,
                average_time_ms=execution_time,
                memory_delta_mb=memory_delta,
                timestamp=datetime.utcnow()
            )
            
            # Add to profiling results
            self.performance_monitor.profiling_results.append(profiling_result)
    
    def get_profiling_report(self) -> Dict[str, Any]:
        """Get profiling report"""
        try:
            # Get recent profiling results
            recent_results = list(self.performance_monitor.profiling_results)[-100:]
            
            # Group by function
            function_stats = defaultdict(list)
            for result in recent_results:
                function_stats[result.function_name].append(result)
            
            # Calculate statistics
            stats = []
            for function_name, results in function_stats.items():
                total_calls = sum(r.call_count for r in results)
                total_time = sum(r.total_time_ms for r in results)
                avg_time = total_time / len(results) if results else 0
                max_time = max(r.total_time_ms for r in results) if results else 0
                min_time = min(r.total_time_ms for r in results) if results else 0
                total_memory = sum(r.memory_delta_mb for r in results)
                avg_memory = total_memory / len(results) if results else 0
                
                stats.append({
                    'function_name': function_name,
                    'call_count': total_calls,
                    'total_time_ms': total_time,
                    'average_time_ms': avg_time,
                    'max_time_ms': max_time,
                    'min_time_ms': min_time,
                    'total_memory_mb': total_memory,
                    'average_memory_mb': avg_memory,
                    'most_recent_call': max(results, key=lambda x: x.timestamp) if results else None
                })
            
            # Sort by total time
            stats.sort(key=lambda x: x['total_time_ms'], reverse=True)
            
            return {
                'total_functions_profiled': len(stats),
                'total_calls': sum(s['call_count'] for s in stats),
                'function_statistics': stats[:20],  # Top 20 functions
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating profiling report: {e}")
            return {'error': str(e)}

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create performance configuration
    config = PerformanceConfig(
        enable_monitoring=True,
        monitoring_interval_seconds=30,
        enable_profiling=True,
        profiling_sample_rate=0.1,
        enable_resource_monitoring=True,
        resource_monitoring_interval_seconds=10,
        enable_database_monitoring=True,
        database_monitoring_interval_seconds=30,
        enable_web_monitoring=True,
        web_monitoring_interval_seconds=15,
        enable_performance_alerting=True,
        alert_thresholds={
            "cpu_usage_percent": 80.0,
            "memory_usage_percent": 85.0,
            "disk_usage_percent": 90.0,
            "response_time_ms": 5000,
            "error_rate_percent": 5.0,
            "garbage_collection_frequency": 100,
            "memory_leak_threshold_mb": 100,
            "slow_queries_per_minute": 10,
            "slow_requests_per_minute": 5
        },
        enable_local_storage=True,
        storage_path="/tmp/performance_monitoring.db",
        enable_prometheus_export=True,
        prometheus_port=9091
    )
    
    print("📊 Performance Monitoring and Profiling Demo")
    print("=" * 50)
    
    # Initialize performance monitor
    try:
        performance_monitor = PerformanceMonitor(config)
        print("✅ Performance monitor initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize performance monitor: {e}")
        exit(1)
    
    # Test system metrics collection
    print("\n1. Testing system metrics collection...")
    try:
        metrics = performance_monitor.get_system_metrics()
        print("✅ System metrics collected successfully")
        print(f"   CPU Usage: {metrics.get('cpu_percent', 0):.2f}%")
        print(f"   Memory Usage: {metrics.get('memory_percent', 0):.2f}%")
        print(f"   Disk Usage: {metrics.get('disk_usage_percent', 0):.2f}%")
        print(f"   Process Count: {metrics.get('process_count', 0)}")
        print(f"   Thread Count: {metrics.get('thread_count', 0)}")
        
    except Exception as e:
        print(f"❌ System metrics collection failed: {e}")
    
    # Test performance summary
    print("\n2. Testing performance summary...")
    try:
        summary = performance_monitor.get_performance_summary()
        print("✅ Performance summary generated successfully")
        if 'error' not in summary:
            print(f"   Average CPU: {summary.get('average_cpu_percent', 0):.2f}%")
            print(f"   Max CPU: {summary.get('max_cpu_percent', 0):.2f}%")
            print(f"   Average Memory: {summary.get('average_memory_percent', 0):.2f}%")
            print(f"   Max Memory: {summary.get('max_memory_percent', 0):.2f}%")
        else:
            print(f"   {summary.get('error', 'Unknown error')}")
        
    except Exception as e:
        print(f"❌ Performance summary generation failed: {e}")
    
    # Test profiler
    print("\n3. Testing function profiler...")
    try:
        profiler = Profiler(performance_monitor)
        
        # Create a test function
        @profiler.profile_function
        def test_function():
            """Test function for profiling"""
            time.sleep(0.1)  # Sleep for 100ms to simulate work
            return "Test completed"
        
        # Execute test function
        result = test_function()
        print("✅ Function profiling test completed")
        print(f"   Result: {result}")
        
        # Get profiling report
        report = profiler.get_profiling_report()
        print("✅ Profiling report generated")
        print(f"   Functions profiled: {report.get('total_functions_profiled', 0)}")
        print(f"   Total calls: {report.get('total_calls', 0)}")
        
    except Exception as e:
        print(f"❌ Function profiling test failed: {e}")
    
    # Test alerting
    print("\n4. Testing alerting system...")
    try:
        # Generate some alerts by simulating high resource usage
        high_cpu_metrics = PerformanceMetrics(
            timestamp=datetime.utcnow(),
            cpu_percent=95.0,  # Above threshold
            memory_percent=75.0,
            memory_rss_mb=1024.0,
            memory_vms_mb=2048.0,
            disk_usage_percent=60.0,
            network_bytes_sent=1000000,
            network_bytes_recv=2000000,
            process_count=100,
            thread_count=200,
            open_file_count=500,
            garbage_collection_count=10,
            garbage_collection_time_ms=50.0
        )
        
        # Check alert conditions
        asyncio.run(performance_monitor._check_alert_conditions(high_cpu_metrics))
        print("✅ Alert conditions checked")
        
        # Get alerts
        alerts = performance_monitor.get_alerts()
        print(f"   Alerts generated: {len(alerts)}")
        if alerts:
            latest_alert = alerts[0]
            print(f"   Latest alert: {latest_alert.get('alert_type', 'unknown')} - {latest_alert.get('severity', 'info')}")
        
    except Exception as e:
        print(f"❌ Alerting system test failed: {e}")
    
    # Test Prometheus metrics
    print("\n5. Testing Prometheus metrics...")
    try:
        # Get current metrics
        metrics = performance_monitor.get_system_metrics()
        
        # Update Prometheus metrics
        performance_monitor._update_prometheus_metrics(
            PerformanceMetrics(**{k: v for k, v in metrics.items() if k != 'timestamp'})
        )
        print("✅ Prometheus metrics updated")
        
    except Exception as e:
        print(f"❌ Prometheus metrics update failed: {e}")
    
    print("\n🎯 Performance Monitoring and Profiling Demo Complete")
    print("This demonstrates the core functionality of the performance monitoring system.")
    print("In a production environment, this would integrate with:")
    print("  • Real system resource monitoring")
    print("  • Database performance monitoring")
    print("  • Web application performance monitoring")
    print("  • Comprehensive alerting and notification systems")
    print("  • Performance data visualization")
    print("  • Automated performance optimization")