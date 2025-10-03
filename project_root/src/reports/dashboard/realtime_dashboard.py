"""
Real-Time Dashboard with WebSocket Updates for Enterprise Reporting System
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import websockets
import aiohttp
from aiohttp import web
import jinja2
import aiofiles
import redis
import pandas as pd
from collections import defaultdict, deque
import secrets
import hashlib
from concurrent.futures import ThreadPoolExecutor
import threading
from prometheus_client import Counter, Histogram, Gauge, generate_latest

logger = logging.getLogger(__name__)

@dataclass
class DashboardConfig:
    """Dashboard configuration"""
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8082
    websocket_port: int = 8083
    
    # Security settings
    enable_authentication: bool = True
    session_timeout_minutes: int = 60
    enable_csrf_protection: bool = True
    allowed_origins: List[str] = None
    
    # Performance settings
    max_concurrent_connections: int = 1000
    websocket_ping_interval: int = 30
    websocket_ping_timeout: int = 10
    enable_compression: bool = True
    compression_level: int = 6
    
    # Caching settings
    enable_caching: bool = True
    cache_ttl_seconds: int = 300
    cache_max_size: int = 1000
    
    # WebSocket settings
    enable_websocket_updates: bool = True
    websocket_buffer_size: int = 100
    websocket_update_interval_ms: int = 1000
    
    # Monitoring settings
    enable_prometheus_metrics: bool = True
    metrics_endpoint: str = "/metrics"
    
    # UI settings
    theme: str = "dark"  # dark, light, auto
    enable_real_time_updates: bool = True
    update_frequency_ms: int = 5000
    enable_animations: bool = True
    
    # Data settings
    max_data_points: int = 1000
    data_retention_hours: int = 24
    enable_data_streaming: bool = True
    
    # Alerting settings
    enable_alert_notifications: bool = True
    alert_update_interval_ms: int = 2000
    
    def __post_init__(self):
        if self.allowed_origins is None:
            self.allowed_origins = ["http://localhost:8082", "https://localhost:8082"]

class WebSocketConnectionManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self, config: DashboardConfig):
        self.config = config
        self.connections = {}
        self.connection_lock = asyncio.Lock()
        self.message_queue = asyncio.Queue()
        self.broadcast_tasks = set()
        self.metrics = {
            'connections_opened': Counter('dashboard_ws_connections_opened_total', 'Total WebSocket connections opened'),
            'connections_closed': Counter('dashboard_ws_connections_closed_total', 'Total WebSocket connections closed'),
            'messages_sent': Counter('dashboard_ws_messages_sent_total', 'Total WebSocket messages sent'),
            'messages_received': Counter('dashboard_ws_messages_received_total', 'Total WebSocket messages received'),
            'broadcast_errors': Counter('dashboard_ws_broadcast_errors_total', 'Total WebSocket broadcast errors'),
            'active_connections': Gauge('dashboard_ws_active_connections', 'Current active WebSocket connections')
        } if config.enable_prometheus_metrics else {}
    
    async def register_connection(self, websocket, client_id: str, subscription_filters: Dict[str, Any] = None):
        """Register a new WebSocket connection"""
        try:
            async with self.connection_lock:
                self.connections[client_id] = {
                    'websocket': websocket,
                    'subscription_filters': subscription_filters or {},
                    'connected_at': datetime.utcnow(),
                    'last_activity': datetime.utcnow(),
                    'message_buffer': deque(maxlen=self.config.websocket_buffer_size)
                }
                
                if self.config.enable_prometheus_metrics:
                    self.metrics['connections_opened'].inc()
                    self.metrics['active_connections'].set(len(self.connections))
                
                logger.info(f"WebSocket connection registered: {client_id}")
                
        except Exception as e:
            logger.error(f"Error registering WebSocket connection {client_id}: {e}")
            raise
    
    async def unregister_connection(self, client_id: str):
        """Unregister a WebSocket connection"""
        try:
            async with self.connection_lock:
                if client_id in self.connections:
                    del self.connections[client_id]
                    
                    if self.config.enable_prometheus_metrics:
                        self.metrics['connections_closed'].inc()
                        self.metrics['active_connections'].set(len(self.connections))
                    
                    logger.info(f"WebSocket connection unregistered: {client_id}")
                    
        except Exception as e:
            logger.error(f"Error unregistering WebSocket connection {client_id}: {e}")
    
    async def send_message(self, client_id: str, message: Dict[str, Any]) -> bool:
        """Send a message to a specific client"""
        try:
            if client_id in self.connections:
                websocket = self.connections[client_id]['websocket']
                
                # Add timestamp to message
                message['timestamp'] = datetime.utcnow().isoformat()
                
                # Send message
                await websocket.send(json.dumps(message, default=str))
                
                if self.config.enable_prometheus_metrics:
                    self.metrics['messages_sent'].inc()
                
                # Update last activity
                self.connections[client_id]['last_activity'] = datetime.utcnow()
                
                return True
            else:
                logger.warning(f"Attempted to send message to disconnected client: {client_id}")
                return False
                
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Connection closed while sending message to {client_id}")
            await self.unregister_connection(client_id)
            return False
        except Exception as e:
            logger.error(f"Error sending message to {client_id}: {e}")
            if self.config.enable_prometheus_metrics:
                self.metrics['broadcast_errors'].inc()
            return False
    
    async def broadcast_message(self, message: Dict[str, Any], 
                               filter_func: Optional[Callable] = None) -> int:
        """Broadcast message to all connected clients (or filtered subset)"""
        try:
            disconnected_clients = []
            sent_count = 0
            
            async with self.connection_lock:
                # Create a copy of connections to avoid modification during iteration
                connections_copy = dict(self.connections)
            
            # Send to all connections
            for client_id, connection_info in connections_copy.items():
                try:
                    # Apply filter if provided
                    if filter_func and not filter_func(client_id, connection_info):
                        continue
                    
                    # Check if connection is still active
                    websocket = connection_info['websocket']
                    if websocket.closed:
                        disconnected_clients.append(client_id)
                        continue
                    
                    # Add timestamp and send
                    message_with_timestamp = message.copy()
                    message_with_timestamp['timestamp'] = datetime.utcnow().isoformat()
                    
                    await websocket.send(json.dumps(message_with_timestamp, default=str))
                    sent_count += 1
                    
                    # Update last activity
                    connection_info['last_activity'] = datetime.utcnow()
                    
                except websockets.exceptions.ConnectionClosed:
                    disconnected_clients.append(client_id)
                except Exception as e:
                    logger.error(f"Error broadcasting to {client_id}: {e}")
                    if self.config.enable_prometheus_metrics:
                        self.metrics['broadcast_errors'].inc()
            
            # Unregister disconnected clients
            for client_id in disconnected_clients:
                await self.unregister_connection(client_id)
            
            # Update metrics
            if self.config.enable_prometheus_metrics:
                self.metrics['messages_sent'].inc(sent_count)
            
            return sent_count
            
        except Exception as e:
            logger.error(f"Error in broadcast_message: {e}")
            if self.config.enable_prometheus_metrics:
                self.metrics['broadcast_errors'].inc()
            return 0
    
    async def handle_client_message(self, client_id: str, message: str):
        """Handle incoming message from client"""
        try:
            # Parse message
            parsed_message = json.loads(message)
            
            if self.config.enable_prometheus_metrics:
                self.metrics['messages_received'].inc()
            
            # Update last activity
            if client_id in self.connections:
                self.connections[client_id]['last_activity'] = datetime.utcnow()
            
            # Process message based on type
            message_type = parsed_message.get('type', 'unknown')
            
            if message_type == 'subscribe':
                await self._handle_subscription(client_id, parsed_message)
            elif message_type == 'unsubscribe':
                await self._handle_unsubscription(client_id, parsed_message)
            elif message_type == 'heartbeat':
                await self._handle_heartbeat(client_id, parsed_message)
            else:
                logger.debug(f"Received unknown message type from {client_id}: {message_type}")
                
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON received from {client_id}")
        except Exception as e:
            logger.error(f"Error handling client message from {client_id}: {e}")
    
    async def _handle_subscription(self, client_id: str, message: Dict[str, Any]):
        """Handle subscription request from client"""
        try:
            if client_id in self.connections:
                # Update subscription filters
                filters = message.get('filters', {})
                self.connections[client_id]['subscription_filters'] = filters
                
                # Send confirmation
                confirmation = {
                    'type': 'subscription_confirmed',
                    'filters': filters,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                await self.send_message(client_id, confirmation)
                logger.info(f"Subscription updated for {client_id}: {filters}")
                
        except Exception as e:
            logger.error(f"Error handling subscription for {client_id}: {e}")
    
    async def _handle_unsubscription(self, client_id: str, message: Dict[str, Any]):
        """Handle unsubscription request from client"""
        try:
            if client_id in self.connections:
                # Clear subscription filters
                self.connections[client_id]['subscription_filters'] = {}
                
                # Send confirmation
                confirmation = {
                    'type': 'unsubscription_confirmed',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                await self.send_message(client_id, confirmation)
                logger.info(f"Unsubscribed {client_id} from all updates")
                
        except Exception as e:
            logger.error(f"Error handling unsubscription for {client_id}: {e}")
    
    async def _handle_heartbeat(self, client_id: str, message: Dict[str, Any]):
        """Handle heartbeat message from client"""
        try:
            # Send heartbeat response
            response = {
                'type': 'heartbeat_response',
                'server_time': datetime.utcnow().isoformat(),
                'timestamp': message.get('timestamp', datetime.utcnow().isoformat())
            }
            
            await self.send_message(client_id, response)
            
        except Exception as e:
            logger.error(f"Error handling heartbeat from {client_id}: {e}")
    
    async def cleanup_inactive_connections(self):
        """Clean up inactive connections"""
        try:
            current_time = datetime.utcnow()
            inactive_clients = []
            
            async with self.connection_lock:
                for client_id, connection_info in self.connections.items():
                    last_activity = connection_info['last_activity']
                    inactive_time = (current_time - last_activity).total_seconds()
                    
                    if inactive_time > self.config.session_timeout_minutes * 60:
                        inactive_clients.append(client_id)
            
            # Unregister inactive clients
            for client_id in inactive_clients:
                logger.info(f"Cleaning up inactive connection: {client_id}")
                await self.unregister_connection(client_id)
                
        except Exception as e:
            logger.error(f"Error cleaning up inactive connections: {e}")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        try:
            async def _get_stats():
                async with self.connection_lock:
                    total_connections = len(self.connections)
                    active_connections = sum(
                        1 for conn in self.connections.values() 
                        if not conn['websocket'].closed
                    ) if self.connections else 0
                    
                    # Calculate average connection duration
                    if self.connections:
                        total_duration = sum(
                            (datetime.utcnow() - conn['connected_at']).total_seconds()
                            for conn in self.connections.values()
                        )
                        avg_duration = total_duration / len(self.connections)
                    else:
                        avg_duration = 0
                    
                    return {
                        'total_connections': total_connections,
                        'active_connections': active_connections,
                        'inactive_connections': total_connections - active_connections,
                        'average_connection_duration_seconds': avg_duration,
                        'timestamp': datetime.utcnow().isoformat()
                    }
            
            # Run in event loop
            try:
                loop = asyncio.get_running_loop()
                future = asyncio.run_coroutine_threadsafe(_get_stats(), loop)
                return future.result(timeout=5)
            except Exception:
                # Fallback if we can't get event loop
                return {
                    'total_connections': len(self.connections),
                    'timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Error getting connection stats: {e}")
            return {'error': str(e)}

class RealTimeDashboardService:
    """Main real-time dashboard service with WebSocket support"""
    
    def __init__(self, config: DashboardConfig):
        self.config = config
        self.ws_manager = WebSocketConnectionManager(config)
        self.app = web.Application()
        self.runner = None
        self.site = None
        self.ws_runner = None
        self.ws_site = None
        self.data_cache = {}
        self.data_cache_lock = threading.Lock()
        self.update_tasks = set()
        self.is_running = False
        
        # Prometheus metrics
        self.metrics = {
            'dashboard_requests_total': Counter('dashboard_requests_total', 'Total dashboard HTTP requests'),
            'dashboard_request_duration_seconds': Histogram('dashboard_request_duration_seconds', 'Dashboard request duration'),
            'active_users': Gauge('dashboard_active_users', 'Current active dashboard users'),
            'data_updates_total': Counter('dashboard_data_updates_total', 'Total data updates sent'),
            'alerts_triggered_total': Counter('dashboard_alerts_triggered_total', 'Total alerts triggered')
        } if config.enable_prometheus_metrics else {}
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup HTTP routes for the dashboard"""
        # Static files
        self.app.router.add_static('/static/', path='/home/cbwinslow/reports/project_root/web/static/', name='static')
        
        # Main dashboard routes
        self.app.router.add_get('/', self.dashboard_handler)
        self.app.router.add_get('/dashboard', self.dashboard_handler)
        self.app.router.add_get('/api/v1/data', self.api_data_handler)
        self.app.router.add_get('/api/v1/stats', self.api_stats_handler)
        self.app.router.add_get('/api/v1/alerts', self.api_alerts_handler)
        self.app.router.add_get('/ws', self.websocket_handler)
        
        # Prometheus metrics endpoint
        if self.config.enable_prometheus_metrics:
            self.app.router.add_get(self.config.metrics_endpoint, self.metrics_handler)
        
        # Add middleware
        self.app.middlewares.append(self.logging_middleware)
        if self.config.enable_compression:
            self.app.middlewares.append(aiohttp.web_middlewares.normalize_path_middleware())
    
    async def logging_middleware(self, app, handler):
        """Middleware for logging requests"""
        async def middleware_handler(request):
            start_time = datetime.utcnow()
            
            if self.config.enable_prometheus_metrics:
                self.metrics['dashboard_requests_total'].inc()
            
            try:
                response = await handler(request)
                return response
            finally:
                duration = (datetime.utcnow() - start_time).total_seconds()
                if self.config.enable_prometheus_metrics:
                    self.metrics['dashboard_request_duration_seconds'].observe(duration)
                
                logger.info(f"{request.method} {request.path} - {duration:.3f}s")
        
        return middleware_handler
    
    async def dashboard_handler(self, request: web.Request) -> web.Response:
        """Serve the main dashboard HTML"""
        try:
            # Simple HTML dashboard
            html_content = self._generate_dashboard_html()
            return web.Response(text=html_content, content_type='text/html')
            
        except Exception as e:
            logger.error(f"Error serving dashboard: {e}")
            return web.Response(text="Dashboard error", status=500)
    
    def _generate_dashboard_html(self) -> str:
        """Generate simple dashboard HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Reporting Dashboard</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5;
        }
        .dashboard { 
            max-width: 1200px; 
            margin: 0 auto; 
        }
        .header { 
            background-color: #2c3e50; 
            color: white; 
            padding: 1rem; 
            border-radius: 5px; 
            margin-bottom: 20px; 
        }
        .cards { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin-bottom: 20px; 
        }
        .card { 
            background-color: white; 
            padding: 1.5rem; 
            border-radius: 5px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .chart-container { 
            background-color: white; 
            padding: 1.5rem; 
            border-radius: 5px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            margin-bottom: 20px; 
        }
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .status-active { background-color: #27ae60; }
        .status-warning { background-color: #f39c12; }
        .status-critical { background-color: #e74c3c; }
        .status-pending { background-color: #95a5a6; }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>Enterprise Reporting Dashboard</h1>
            <p>Real-time system monitoring and analytics</p>
        </div>
        
        <div class="cards">
            <div class="card">
                <h3>System Status</h3>
                <p><span class="status-indicator status-active"></span> All Systems Operational</p>
                <p>Uptime: 99.98%</p>
            </div>
            
            <div class="card">
                <h3>Active Alerts</h3>
                <p><span class="status-indicator status-warning"></span> 2 Warnings</p>
                <p><span class="status-indicator status-critical"></span> 0 Critical</p>
            </div>
            
            <div class="card">
                <h3>System Load</h3>
                <p>CPU: 23%</p>
                <p>Memory: 45%</p>
                <p>Disk: 67%</p>
            </div>
            
            <div class="card">
                <h3>Recent Activity</h3>
                <p>Systems Monitored: 45</p>
                <p>Reports Generated: 156</p>
                <p>Alerts Processed: 23</p>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>Real-time Metrics</h3>
            <div id="metrics-placeholder">
                <p>Connecting to real-time data feed...</p>
                <div id="websocket-status">
                    <button onclick="connectWebSocket()">Connect</button>
                    <span id="connection-status">Disconnected</span>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let ws = null;
        
        function connectWebSocket() {
            if (ws && ws.readyState === WebSocket.OPEN) {
                console.log("Already connected");
                return;
            }
            
            const wsUrl = `ws://${window.location.host}/ws`;
            ws = new WebSocket(wsUrl);
            
            ws.onopen = function(event) {
                console.log("WebSocket connected");
                document.getElementById('connection-status').textContent = 'Connected';
                document.getElementById('connection-status').style.color = 'green';
                
                // Subscribe to updates
                ws.send(JSON.stringify({
                    type: 'subscribe',
                    filters: { 'category': 'all' }
                }));
            };
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                console.log("Received:", data);
                
                // Update UI with real-time data
                updateDashboard(data);
            };
            
            ws.onclose = function(event) {
                console.log("WebSocket disconnected");
                document.getElementById('connection-status').textContent = 'Disconnected';
                document.getElementById('connection-status').style.color = 'red';
            };
            
            ws.onerror = function(error) {
                console.error("WebSocket error:", error);
                document.getElementById('connection-status').textContent = 'Error';
                document.getElementById('connection-status').style.color = 'red';
            };
        }
        
        function updateDashboard(data) {
            // Update dashboard elements with real-time data
            const placeholder = document.getElementById('metrics-placeholder');
            placeholder.innerHTML = `
                <h4>Latest Update</h4>
                <p>Type: ${data.type || 'N/A'}</p>
                <p>Timestamp: ${data.timestamp || 'N/A'}</p>
                <pre>${JSON.stringify(data, null, 2)}</pre>
            `;
        }
        
        // Auto-connect on page load
        window.addEventListener('load', function() {
            setTimeout(connectWebSocket, 1000);  // Wait a bit for page to load
        });
    </script>
</body>
</html>
        """
    
    async def api_data_handler(self, request: web.Request) -> web.Response:
        """API endpoint for dashboard data"""
        try:
            # Get query parameters
            data_type = request.query.get('type', 'summary')
            limit = int(request.query.get('limit', 100))
            
            # Get cached data or generate fresh data
            cache_key = f"api_data_{data_type}_{limit}"
            data = self._get_cached_data(cache_key)
            
            if data is None:
                data = await self._generate_api_data(data_type, limit)
                self._cache_data(cache_key, data)
            
            return web.json_response(data)
            
        except Exception as e:
            logger.error(f"Error in API data handler: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _generate_api_data(self, data_type: str, limit: int) -> Dict[str, Any]:
        """Generate API data based on type"""
        if data_type == 'summary':
            return {
                'type': 'summary',
                'timestamp': datetime.utcnow().isoformat(),
                'systems_monitored': 45,
                'active_alerts': 2,
                'reports_generated': 156,
                'system_uptime': '99.98%',
                'cpu_usage': 23.4,
                'memory_usage': 45.2,
                'disk_usage': 67.1
            }
        elif data_type == 'metrics':
            # Generate time-series metrics
            timestamps = []
            cpu_data = []
            memory_data = []
            disk_data = []
            
            for i in range(limit):
                timestamp = (datetime.utcnow() - timedelta(minutes=i*5)).isoformat()
                timestamps.append(timestamp)
                cpu_data.append(20 + (i % 10))  # Simulate CPU usage
                memory_data.append(40 + (i % 15))  # Simulate memory usage
                disk_data.append(60 + (i % 20))  # Simulate disk usage
            
            return {
                'type': 'metrics',
                'timestamps': timestamps,
                'cpu_usage': cpu_data,
                'memory_usage': memory_data,
                'disk_usage': disk_data
            }
        else:
            return {
                'type': data_type,
                'timestamp': datetime.utcnow().isoformat(),
                'data': f"Sample data for {data_type}"
            }
    
    async def api_stats_handler(self, request: web.Request) -> web.Response:
        """API endpoint for system statistics"""
        try:
            stats = {
                'timestamp': datetime.utcnow().isoformat(),
                'connections': self.ws_manager.get_connection_stats(),
                'cache_stats': self._get_cache_stats(),
                'system_stats': await self._get_system_stats()
            }
            
            return web.json_response(stats)
            
        except Exception as e:
            logger.error(f"Error in stats handler: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def api_alerts_handler(self, request: web.Request) -> web.Response:
        """API endpoint for alerts"""
        try:
            # Mock alert data
            alerts = [
                {
                    'id': 'alert_1',
                    'severity': 'warning',
                    'title': 'High CPU Usage',
                    'description': 'CPU usage exceeded 80% on server-01',
                    'timestamp': (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
                    'status': 'active'
                },
                {
                    'id': 'alert_2',
                    'severity': 'warning',
                    'title': 'Disk Space Low',
                    'description': 'Disk usage at 85% on server-02',
                    'timestamp': (datetime.utcnow() - timedelta(minutes=15)).isoformat(),
                    'status': 'active'
                }
            ]
            
            return web.json_response({
                'alerts': alerts,
                'total_alerts': len(alerts),
                'active_alerts': len([a for a in alerts if a['status'] == 'active'])
            })
            
        except Exception as e:
            logger.error(f"Error in alerts handler: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """WebSocket handler for real-time updates"""
        try:
            # Create WebSocket response
            ws = web.WebSocketResponse(
                autoping=True,
                heartbeat=self.config.websocket_ping_interval
            )
            
            # Prepare WebSocket
            await ws.prepare(request)
            
            # Generate unique client ID
            client_id = f"client_{secrets.token_urlsafe(16)}"
            
            # Register connection
            await self.ws_manager.register_connection(ws, client_id)
            
            # Handle messages
            try:
                async for msg in ws:
                    if msg.type == web.WSMsgType.TEXT:
                        await self.ws_manager.handle_client_message(client_id, msg.data)
                    elif msg.type == web.WSMsgType.ERROR:
                        logger.error(f"WebSocket error: {ws.exception()}")
                        
            except Exception as e:
                logger.error(f"Error in WebSocket message handling: {e}")
            
            finally:
                # Unregister connection
                await self.ws_manager.unregister_connection(client_id)
            
            return ws
            
        except Exception as e:
            logger.error(f"Error in WebSocket handler: {e}")
            raise
    
    async def metrics_handler(self, request: web.Request) -> web.Response:
        """Prometheus metrics endpoint"""
        try:
            if not self.config.enable_prometheus_metrics:
                return web.Response(text="Metrics disabled", status=404)
            
            # Generate Prometheus metrics
            metrics_data = generate_latest()
            return web.Response(
                text=metrics_data.decode('utf-8'),
                content_type='text/plain; version=0.0.4'
            )
            
        except Exception as e:
            logger.error(f"Error in metrics handler: {e}")
            return web.Response(text="Metrics error", status=500)
    
    async def _get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        try:
            # Mock system stats - in real implementation, this would get actual system metrics
            return {
                'cpu_count': 8,
                'memory_total_gb': 32.0,
                'disk_total_gb': 500.0,
                'network_interfaces': 2,
                'process_count': 156
            }
        except Exception as e:
            logger.error(f"Error getting system stats: {e}")
            return {'error': str(e)}
    
    def _get_cached_data(self, key: str) -> Optional[Any]:
        """Get data from cache"""
        if not self.config.enable_caching:
            return None
        
        try:
            with self.data_cache_lock:
                if key in self.data_cache:
                    data, timestamp = self.data_cache[key]
                    if (datetime.utcnow() - timestamp).total_seconds() < self.config.cache_ttl_seconds:
                        return data
                    else:
                        # Remove expired cache entry
                        del self.data_cache[key]
            return None
        except Exception as e:
            logger.debug(f"Error getting cached data: {e}")
            return None
    
    def _cache_data(self, key: str, data: Any):
        """Cache data"""
        if not self.config.enable_caching:
            return
        
        try:
            with self.data_cache_lock:
                # Remove oldest entries if cache is full
                if len(self.data_cache) >= self.config.cache_max_size:
                    oldest_key = min(self.data_cache.keys(), 
                                   key=lambda k: self.data_cache[k][1])
                    del self.data_cache[oldest_key]
                
                # Add new entry
                self.data_cache[key] = (data, datetime.utcnow())
        except Exception as e:
            logger.debug(f"Error caching data: {e}")
    
    def _get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            with self.data_cache_lock:
                return {
                    'cache_size': len(self.data_cache),
                    'max_cache_size': self.config.cache_max_size,
                    'cache_enabled': self.config.enable_caching
                }
        except Exception as e:
            logger.debug(f"Error getting cache stats: {e}")
            return {'error': str(e)}
    
    async def start_dashboard(self):
        """Start the dashboard service"""
        try:
            # Create runners
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            
            # Create sites
            self.site = web.TCPSite(
                self.runner, 
                self.config.host, 
                self.config.port
            )
            
            # Start HTTP server
            await self.site.start()
            logger.info(f"Dashboard HTTP server started on {self.config.host}:{self.config.port}")
            
            # Start background tasks
            self._start_background_tasks()
            
            self.is_running = True
            
        except Exception as e:
            logger.error(f"Error starting dashboard: {e}")
            raise
    
    async def stop_dashboard(self):
        """Stop the dashboard service"""
        try:
            self.is_running = False
            
            # Stop background tasks
            await self._stop_background_tasks()
            
            # Stop HTTP server
            if self.site:
                await self.site.stop()
            
            if self.runner:
                await self.runner.cleanup()
            
            # Close WebSocket connections
            await self._close_all_websocket_connections()
            
            logger.info("Dashboard service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping dashboard: {e}")
    
    def _start_background_tasks(self):
        """Start background tasks"""
        # Start data update task
        if self.config.enable_real_time_updates:
            update_task = asyncio.create_task(self._data_update_task())
            self.update_tasks.add(update_task)
            update_task.add_done_callback(self.update_tasks.discard)
        
        # Start connection cleanup task
        cleanup_task = asyncio.create_task(self._connection_cleanup_task())
        self.update_tasks.add(cleanup_task)
        cleanup_task.add_done_callback(self.update_tasks.discard)
        
        # Start alert monitoring task
        if self.config.enable_alert_notifications:
            alert_task = asyncio.create_task(self._alert_monitoring_task())
            self.update_tasks.add(alert_task)
            alert_task.add_done_callback(self.update_tasks.discard)
    
    async def _stop_background_tasks(self):
        """Stop background tasks"""
        for task in self.update_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.update_tasks:
            await asyncio.gather(*self.update_tasks, return_exceptions=True)
    
    async def _data_update_task(self):
        """Background task for sending data updates"""
        try:
            while self.is_running:
                try:
                    # Generate sample data update
                    data_update = {
                        'type': 'data_update',
                        'timestamp': datetime.utcnow().isoformat(),
                        'cpu_usage': 20 + (datetime.utcnow().second % 10),
                        'memory_usage': 40 + (datetime.utcnow().second % 15),
                        'disk_usage': 60 + (datetime.utcnow().second % 20),
                        'active_connections': len(self.ws_manager.connections)
                    }
                    
                    # Broadcast to all connected clients
                    await self.ws_manager.broadcast_message(data_update)
                    
                    # Wait for next update
                    await asyncio.sleep(self.config.update_frequency_ms / 1000)
                    
                except asyncio.CancelledError:
                    logger.info("Data update task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in data update task: {e}")
                    await asyncio.sleep(5)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Fatal error in data update task: {e}")
    
    async def _connection_cleanup_task(self):
        """Background task for cleaning up inactive connections"""
        try:
            while self.is_running:
                try:
                    # Clean up inactive connections
                    await self.ws_manager.cleanup_inactive_connections()
                    
                    # Wait for next cleanup
                    await asyncio.sleep(300)  # 5 minutes
                    
                except asyncio.CancelledError:
                    logger.info("Connection cleanup task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in connection cleanup task: {e}")
                    await asyncio.sleep(60)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Fatal error in connection cleanup task: {e}")
    
    async def _alert_monitoring_task(self):
        """Background task for monitoring and broadcasting alerts"""
        try:
            while self.is_running:
                try:
                    # Generate sample alert update
                    alert_update = {
                        'type': 'alert_update',
                        'timestamp': datetime.utcnow().isoformat(),
                        'alerts': [
                            {
                                'id': f'alert_{datetime.utcnow().timestamp()}',
                                'severity': 'info',
                                'message': 'System check completed successfully',
                                'timestamp': datetime.utcnow().isoformat()
                            }
                        ]
                    }
                    
                    # Broadcast alert update
                    await self.ws_manager.broadcast_message(
                        alert_update,
                        lambda cid, conn: conn['subscription_filters'].get('category') == 'alerts'
                    )
                    
                    # Increment alert counter
                    if self.config.enable_prometheus_metrics:
                        self.metrics['alerts_triggered_total'].inc()
                    
                    # Wait for next alert check
                    await asyncio.sleep(self.config.alert_update_interval_ms / 1000)
                    
                except asyncio.CancelledError:
                    logger.info("Alert monitoring task cancelled")
                    break
                except Exception as e:
                    logger.error(f"Error in alert monitoring task: {e}")
                    await asyncio.sleep(10)  # Wait before retrying
                    
        except Exception as e:
            logger.error(f"Fatal error in alert monitoring task: {e}")
    
    async def _close_all_websocket_connections(self):
        """Close all WebSocket connections"""
        try:
            async with self.ws_manager.connection_lock:
                for client_id, connection_info in self.ws_manager.connections.items():
                    try:
                        websocket = connection_info['websocket']
                        if not websocket.closed:
                            await websocket.close(
                                code=1001,  # Going away
                                message=b"Server shutting down"
                            )
                    except Exception as e:
                        logger.debug(f"Error closing connection {client_id}: {e}")
                
                # Clear connections
                self.ws_manager.connections.clear()
                
                if self.config.enable_prometheus_metrics:
                    self.metrics['active_connections'].set(0)
                
        except Exception as e:
            logger.error(f"Error closing WebSocket connections: {e}")

class DashboardAnalytics:
    """Analytics for dashboard usage and performance"""
    
    def __init__(self, dashboard_service: RealTimeDashboardService):
        self.dashboard_service = dashboard_service
        self.analytics_data = {
            'page_views': defaultdict(int),
            'user_sessions': defaultdict(list),
            'feature_usage': defaultdict(int),
            'error_counts': defaultdict(int),
            'performance_metrics': deque(maxlen=1000)
        }
        self.analytics_lock = threading.Lock()
    
    def record_page_view(self, page: str, user_id: Optional[str] = None):
        """Record a page view"""
        try:
            with self.analytics_lock:
                self.analytics_data['page_views'][page] += 1
                
                if user_id:
                    session_data = {
                        'user_id': user_id,
                        'timestamp': datetime.utcnow(),
                        'page': page
                    }
                    self.analytics_data['user_sessions'][user_id].append(session_data)
        
        except Exception as e:
            logger.debug(f"Error recording page view: {e}")
    
    def record_feature_usage(self, feature: str):
        """Record feature usage"""
        try:
            with self.analytics_lock:
                self.analytics_data['feature_usage'][feature] += 1
        
        except Exception as e:
            logger.debug(f"Error recording feature usage: {e}")
    
    def record_error(self, error_type: str, error_message: str):
        """Record an error"""
        try:
            with self.analytics_lock:
                self.analytics_data['error_counts'][error_type] += 1
                
                # Log error details
                logger.error(f"Dashboard error [{error_type}]: {error_message}")
        
        except Exception as e:
            logger.debug(f"Error recording error: {e}")
    
    def record_performance_metric(self, metric_name: str, value: float, 
                                 timestamp: Optional[datetime] = None):
        """Record a performance metric"""
        try:
            if timestamp is None:
                timestamp = datetime.utcnow()
            
            with self.analytics_lock:
                self.analytics_data['performance_metrics'].append({
                    'metric_name': metric_name,
                    'value': value,
                    'timestamp': timestamp
                })
        
        except Exception as e:
            logger.debug(f"Error recording performance metric: {e}")
    
    def get_analytics_summary(self) -> Dict[str, Any]:
        """Get analytics summary"""
        try:
            with self.analytics_lock:
                # Calculate summary statistics
                total_page_views = sum(self.analytics_data['page_views'].values())
                total_users = len(self.analytics_data['user_sessions'])
                total_features = sum(self.analytics_data['feature_usage'].values())
                total_errors = sum(self.analytics_data['error_counts'].values())
                
                # Get recent performance metrics
                recent_metrics = list(self.analytics_data['performance_metrics'])
                
                return {
                    'summary': {
                        'total_page_views': total_page_views,
                        'unique_users': total_users,
                        'feature_interactions': total_features,
                        'errors_logged': total_errors,
                        'timestamp': datetime.utcnow().isoformat()
                    },
                    'page_views': dict(self.analytics_data['page_views']),
                    'feature_usage': dict(self.analytics_data['feature_usage']),
                    'error_counts': dict(self.analytics_data['error_counts']),
                    'recent_performance': recent_metrics[-10:] if recent_metrics else [],
                    'active_connections': len(self.dashboard_service.ws_manager.connections)
                }
                
        except Exception as e:
            logger.error(f"Error getting analytics summary: {e}")
            return {'error': str(e)}

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create dashboard configuration
    config = DashboardConfig(
        host="localhost",
        port=8082,
        websocket_port=8083,
        enable_real_time_updates=True,
        update_frequency_ms=2000,  # 2 seconds
        enable_alert_notifications=True,
        alert_update_interval_ms=5000,  # 5 seconds
        enable_prometheus_metrics=True,
        metrics_endpoint="/metrics"
    )
    
    print("📊 Real-Time Dashboard Demo")
    print("=" * 40)
    
    # Initialize dashboard service
    try:
        dashboard_service = RealTimeDashboardService(config)
        print("✅ Dashboard service initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize dashboard service: {e}")
        exit(1)
    
    # Start dashboard
    print("\n🚀 Starting dashboard service...")
    try:
        # Start the dashboard service
        loop = asyncio.get_event_loop()
        loop.run_until_complete(dashboard_service.start_dashboard())
        
        print("✅ Dashboard service started successfully")
        print(f"   Dashboard URL: http://{config.host}:{config.port}")
        print(f"   WebSocket URL: ws://{config.host}:{config.websocket_port}/ws")
        print(f"   Metrics URL: http://{config.host}:{config.port}{config.metrics_endpoint}")
        print("\n🔧 Press Ctrl+C to stop the dashboard")
        
        # Keep the service running
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            print("\n🛑 Stopping dashboard service...")
            loop.run_until_complete(dashboard_service.stop_dashboard())
            print("✅ Dashboard service stopped")
        
    except Exception as e:
        print(f"❌ Error starting dashboard service: {e}")
        exit(1)
    
    print("\n🎯 Real-Time Dashboard Demo Complete")
    print("This demonstrates the core functionality of the real-time dashboard.")
    print("In a production environment, this would integrate with:")
    print("  • Actual data sources and real-time metrics")
    print("  • Authentication and authorization systems")
    print("  • Load balancing and high availability")
    print("  • Comprehensive monitoring and alerting")
    print("  • Advanced security features")