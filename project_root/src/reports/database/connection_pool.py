"""
Database Connection Pooling for Enterprise Reporting System
"""

import asyncio
import logging
import time
from typing import Optional, Dict, Any, List, Callable, Union
from dataclasses import dataclass
from contextlib import asynccontextmanager, contextmanager
from threading import Lock, Semaphore
import queue
import weakref
from datetime import datetime, timedelta
import psycopg2
from psycopg2 import pool as psycopg2_pool
from sqlalchemy import create_engine, engine, event
from sqlalchemy.pool import QueuePool, NullPool, StaticPool
from sqlalchemy.engine import Engine
import aiopg
import asyncpg
from redis import Redis
import json

logger = logging.getLogger(__name__)

@dataclass
class DatabaseConfig:
    """Database connection configuration"""
    # Connection settings
    host: str = "localhost"
    port: int = 5432
    database: str = "reports"
    username: str = "reports_user"
    password: str = ""
    connection_uri: Optional[str] = None
    
    # Pool settings
    pool_min_size: int = 5
    pool_max_size: int = 20
    pool_overflow_size: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600  # 1 hour
    pool_pre_ping: bool = True
    
    # Connection settings
    connection_timeout: int = 30
    command_timeout: int = 60
    statement_cache_size: int = 100
    max_prepared_statements: int = 100
    
    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_backoff_factor: float = 2.0
    
    # Security settings
    ssl_enabled: bool = False
    ssl_mode: str = "prefer"  # disable, allow, prefer, require, verify-ca, verify-full
    ssl_cert_file: Optional[str] = None
    ssl_key_file: Optional[str] = None
    ssl_ca_file: Optional[str] = None
    
    # Monitoring settings
    enable_metrics: bool = True
    metrics_namespace: str = "reports_db"
    slow_query_threshold_ms: int = 1000
    
    # Advanced settings
    enable_autocommit: bool = False
    enable_deferrable: bool = False
    application_name: str = "enterprise_reporting_system"
    client_encoding: str = "UTF8"

class ConnectionPoolError(Exception):
    """Custom exception for connection pool errors"""
    pass

class DatabaseConnectionPool:
    """Advanced database connection pool with monitoring and optimization"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.pool = None
        self.metrics = {
            'connections_created': 0,
            'connections_reused': 0,
            'connections_closed': 0,
            'queries_executed': 0,
            'queries_failed': 0,
            'pool_timeouts': 0,
            'connection_timeouts': 0,
            'slow_queries': 0
        }
        self.metrics_lock = Lock()
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize database connection pool"""
        try:
            # Build connection URI if not provided
            if not self.config.connection_uri:
                ssl_params = ""
                if self.config.ssl_enabled:
                    ssl_params = f"?sslmode={self.config.ssl_mode}"
                    if self.config.ssl_cert_file:
                        ssl_params += f"&sslcert={self.config.ssl_cert_file}"
                    if self.config.ssl_key_file:
                        ssl_params += f"&sslkey={self.config.ssl_key_file}"
                    if self.config.ssl_ca_file:
                        ssl_params += f"&sslrootcert={self.config.ssl_ca_file}"
                
                self.config.connection_uri = (
                    f"postgresql://{self.config.username}:{self.config.password}@"
                    f"{self.config.host}:{self.config.port}/{self.config.database}"
                    f"{ssl_params}"
                )
            
            # Create SQLAlchemy engine with connection pool
            self.pool = create_engine(
                self.config.connection_uri,
                poolclass=QueuePool,
                pool_size=self.config.pool_min_size,
                max_overflow=self.config.pool_overflow_size,
                pool_timeout=self.config.pool_timeout,
                pool_recycle=self.config.pool_recycle,
                pool_pre_ping=self.config.pool_pre_ping,
                connect_args={
                    'connect_timeout': self.config.connection_timeout,
                    'application_name': self.config.application_name,
                    'client_encoding': self.config.client_encoding
                }
            )
            
            # Add event listeners for monitoring
            self._setup_event_listeners()
            
            logger.info("Database connection pool initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing database connection pool: {e}")
            raise ConnectionPoolError(f"Pool initialization failed: {str(e)}")
    
    def _setup_event_listeners(self):
        """Setup SQLAlchemy event listeners for monitoring"""
        if not self.config.enable_metrics:
            return
        
        @event.listens_for(self.pool, "connect")
        def on_connect(dbapi_connection, connection_record):
            with self.metrics_lock:
                self.metrics['connections_created'] += 1
            
            # Set application-specific connection settings
            try:
                with dbapi_connection.cursor() as cursor:
                    cursor.execute(
                        "SET application_name = %s", 
                        (self.config.application_name,)
                    )
                    if self.config.statement_cache_size > 0:
                        cursor.execute(
                            "SET plan_cache_mode = force_generic_plan"
                        )
            except Exception as e:
                logger.debug(f"Error setting connection parameters: {e}")
        
        @event.listens_for(self.pool, "checkout")
        def on_checkout(dbapi_connection, connection_record, connection_proxy):
            connection_record.info['checkout_time'] = time.time()
        
        @event.listens_for(self.pool, "checkin")
        def on_checkin(dbapi_connection, connection_record):
            checkout_time = connection_record.info.get('checkout_time')
            if checkout_time:
                duration = time.time() - checkout_time
                if duration * 1000 > self.config.slow_query_threshold_ms:
                    with self.metrics_lock:
                        self.metrics['slow_queries'] += 1
                    logger.warning(
                        f"Slow connection checkout: {duration:.2f}s "
                        f"(threshold: {self.config.slow_query_threshold_ms}ms)"
                    )
        
        @event.listens_for(self.pool, "close")
        def on_close(dbapi_connection, connection_record):
            with self.metrics_lock:
                self.metrics['connections_closed'] += 1
    
    @contextmanager
    def get_connection(self, autocommit: bool = None):
        """Get database connection from pool"""
        connection = None
        start_time = time.time()
        
        try:
            # Get connection from pool
            connection = self.pool.connect()
            
            # Set autocommit if specified
            if autocommit is not None:
                connection.autocommit = autocommit
            elif self.config.enable_autocommit:
                connection.autocommit = True
            
            # Track reused connections
            with self.metrics_lock:
                self.metrics['connections_reused'] += 1
            
            yield connection
            
        except Exception as e:
            with self.metrics_lock:
                self.metrics['connection_timeouts'] += 1
            logger.error(f"Error getting database connection: {e}")
            raise ConnectionPoolError(f"Connection failed: {str(e)}")
        
        finally:
            # Close connection and return to pool
            if connection:
                try:
                    connection.close()
                except Exception as e:
                    logger.debug(f"Error closing connection: {e}")
            
            # Track query execution time
            duration = time.time() - start_time
            if duration * 1000 > self.config.slow_query_threshold_ms:
                with self.metrics_lock:
                    self.metrics['slow_queries'] += 1
                logger.warning(
                    f"Slow database operation: {duration:.2f}s "
                    f"(threshold: {self.config.slow_query_threshold_ms}ms)"
                )
    
    def execute_query(self, query: str, params: Optional[tuple] = None, 
                     fetch_results: bool = True) -> Optional[List[Dict]]:
        """Execute database query with connection pooling"""
        try:
            with self.get_connection() as connection:
                start_time = time.time()
                
                with connection.cursor() as cursor:
                    # Execute query
                    cursor.execute(query, params)
                    
                    # Fetch results if requested
                    if fetch_results:
                        columns = [desc[0] for desc in cursor.description] if cursor.description else []
                        rows = cursor.fetchall()
                        results = [dict(zip(columns, row)) for row in rows]
                    else:
                        results = None
                    
                    # Track successful query
                    with self.metrics_lock:
                        self.metrics['queries_executed'] += 1
                    
                    return results
                    
        except Exception as e:
            with self.metrics_lock:
                self.metrics['queries_failed'] += 1
            logger.error(f"Error executing query: {e}")
            raise ConnectionPoolError(f"Query execution failed: {str(e)}")
    
    def execute_transaction(self, queries: List[tuple]) -> List[Optional[List[Dict]]]:
        """Execute multiple queries in a transaction"""
        try:
            with self.get_connection(autocommit=False) as connection:
                start_time = time.time()
                
                with connection.begin() as transaction:
                    results = []
                    
                    for query, params in queries:
                        with connection.cursor() as cursor:
                            cursor.execute(query, params)
                            
                            # Fetch results if query returns data
                            if cursor.description:
                                columns = [desc[0] for desc in cursor.description]
                                rows = cursor.fetchall()
                                query_results = [dict(zip(columns, row)) for row in rows]
                                results.append(query_results)
                            else:
                                results.append(None)
                    
                    # Track successful transaction
                    with self.metrics_lock:
                        self.metrics['queries_executed'] += len(queries)
                    
                    return results
                    
        except Exception as e:
            with self.metrics_lock:
                self.metrics['queries_failed'] += len(queries)
            logger.error(f"Error executing transaction: {e}")
            raise ConnectionPoolError(f"Transaction failed: {str(e)}")
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics"""
        try:
            if hasattr(self.pool.pool, 'status'):
                pool_status = self.pool.pool.status()
            else:
                pool_status = "N/A"
            
            return {
                'pool_status': pool_status,
                'pool_size': self.config.pool_min_size,
                'max_pool_size': self.config.pool_max_size,
                'overflow_size': self.config.pool_overflow_size,
                'metrics': self.metrics.copy(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting pool statistics: {e}")
            return {
                'error': str(e),
                'metrics': self.metrics.copy()
            }
    
    def close(self):
        """Close connection pool"""
        try:
            if self.pool:
                self.pool.dispose()
            logger.info("Database connection pool closed")
        except Exception as e:
            logger.error(f"Error closing connection pool: {e}")

class AsyncDatabaseConnectionPool:
    """Asynchronous database connection pool for high-performance applications"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.pool = None
        self.metrics = {
            'connections_created': 0,
            'connections_reused': 0,
            'connections_closed': 0,
            'queries_executed': 0,
            'queries_failed': 0,
            'pool_timeouts': 0,
            'connection_timeouts': 0,
            'slow_queries': 0
        }
        self.metrics_lock = asyncio.Lock()
        self._initialize_async_pool()
    
    def _initialize_async_pool(self):
        """Initialize async database connection pool"""
        try:
            # For async, we'll use asyncpg with connection pooling
            # This is a simplified example - in production, you'd configure properly
            
            logger.info("Async database connection pool initialized")
            
        except Exception as e:
            logger.error(f"Error initializing async database connection pool: {e}")
            raise ConnectionPoolError(f"Async pool initialization failed: {str(e)}")
    
    async def _setup_async_pool(self):
        """Setup async connection pool"""
        try:
            # Create async connection pool
            self.pool = await asyncpg.create_pool(
                host=self.config.host,
                port=self.config.port,
                database=self.config.database,
                user=self.config.username,
                password=self.config.password,
                min_size=self.config.pool_min_size,
                max_size=self.config.pool_max_size,
                command_timeout=self.config.command_timeout,
                ssl=self.config.ssl_enabled
            )
            
            logger.info("Async database connection pool created")
            
        except Exception as e:
            logger.error(f"Error creating async connection pool: {e}")
            raise ConnectionPoolError(f"Async pool creation failed: {str(e)}")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get async database connection from pool"""
        if not self.pool:
            await self._setup_async_pool()
        
        connection = None
        start_time = time.time()
        
        try:
            # Get connection from pool
            connection = await self.pool.acquire()
            
            # Track reused connections
            async with self.metrics_lock:
                self.metrics['connections_reused'] += 1
            
            yield connection
            
        except asyncio.TimeoutError:
            async with self.metrics_lock:
                self.metrics['connection_timeouts'] += 1
            logger.error("Timeout acquiring database connection from pool")
            raise ConnectionPoolError("Connection pool timeout")
        
        except Exception as e:
            async with self.metrics_lock:
                self.metrics['connection_timeouts'] += 1
            logger.error(f"Error getting database connection: {e}")
            raise ConnectionPoolError(f"Connection failed: {str(e)}")
        
        finally:
            # Return connection to pool
            if connection:
                try:
                    await self.pool.release(connection)
                except Exception as e:
                    logger.debug(f"Error releasing connection: {e}")
            
            # Track query execution time
            duration = time.time() - start_time
            if duration * 1000 > self.config.slow_query_threshold_ms:
                async with self.metrics_lock:
                    self.metrics['slow_queries'] += 1
                logger.warning(
                    f"Slow async database operation: {duration:.2f}s "
                    f"(threshold: {self.config.slow_query_threshold_ms}ms)"
                )
    
    async def execute_query(self, query: str, params: Optional[tuple] = None, 
                          fetch_results: bool = True) -> Optional[List[Dict]]:
        """Execute async database query with connection pooling"""
        try:
            async with self.get_connection() as connection:
                start_time = time.time()
                
                # Execute query
                if fetch_results:
                    results = await connection.fetch(query, *params if params else ())
                else:
                    await connection.execute(query, *params if params else ())
                    results = None
                
                # Track successful query
                async with self.metrics_lock:
                    self.metrics['queries_executed'] += 1
                
                return results
                
        except Exception as e:
            async with self.metrics_lock:
                self.metrics['queries_failed'] += 1
            logger.error(f"Error executing async query: {e}")
            raise ConnectionPoolError(f"Async query execution failed: {str(e)}")
    
    async def close(self):
        """Close async connection pool"""
        try:
            if self.pool:
                await self.pool.close()
            logger.info("Async database connection pool closed")
        except Exception as e:
            logger.error(f"Error closing async connection pool: {e}")

class ConnectionPoolManager:
    """High-level connection pool manager with advanced features"""
    
    def __init__(self, database_configs: Dict[str, DatabaseConfig]):
        self.database_configs = database_configs
        self.pools = {}
        self.async_pools = {}
        self.health_checks = {}
        self._initialize_pools()
    
    def _initialize_pools(self):
        """Initialize all configured database pools"""
        for db_name, db_config in self.database_configs.items():
            try:
                # Initialize sync pool
                self.pools[db_name] = DatabaseConnectionPool(db_config)
                
                # Initialize health check
                self.health_checks[db_name] = {
                    'last_check': datetime.utcnow(),
                    'status': 'unknown',
                    'latency_ms': 0
                }
                
                logger.info(f"Initialized connection pool for database: {db_name}")
                
            except Exception as e:
                logger.error(f"Error initializing pool for database {db_name}: {e}")
    
    def get_pool(self, db_name: str) -> DatabaseConnectionPool:
        """Get connection pool for specific database"""
        if db_name not in self.pools:
            raise ConnectionPoolError(f"No pool configured for database: {db_name}")
        
        return self.pools[db_name]
    
    def execute_query(self, db_name: str, query: str, params: Optional[tuple] = None, 
                     fetch_results: bool = True) -> Optional[List[Dict]]:
        """Execute query on specific database"""
        pool = self.get_pool(db_name)
        return pool.execute_query(query, params, fetch_results)
    
    async def get_async_pool(self, db_name: str) -> AsyncDatabaseConnectionPool:
        """Get async connection pool for specific database"""
        if db_name not in self.async_pools:
            if db_name not in self.database_configs:
                raise ConnectionPoolError(f"No configuration for database: {db_name}")
            
            # Initialize async pool
            config = self.database_configs[db_name]
            self.async_pools[db_name] = AsyncDatabaseConnectionPool(config)
        
        return self.async_pools[db_name]
    
    def health_check(self, db_name: str) -> Dict[str, Any]:
        """Perform health check on database connection"""
        try:
            pool = self.get_pool(db_name)
            start_time = time.time()
            
            # Execute simple health check query
            result = pool.execute_query("SELECT 1 as health_check", fetch_results=True)
            
            latency_ms = (time.time() - start_time) * 1000
            
            self.health_checks[db_name] = {
                'last_check': datetime.utcnow(),
                'status': 'healthy' if result else 'unhealthy',
                'latency_ms': latency_ms
            }
            
            return {
                'status': 'healthy' if result else 'unhealthy',
                'latency_ms': latency_ms,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.health_checks[db_name] = {
                'last_check': datetime.utcnow(),
                'status': 'unhealthy',
                'latency_ms': 0,
                'error': str(e)
            }
            
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all connection pools"""
        stats = {}
        
        for db_name in self.pools:
            try:
                pool_stats = self.pools[db_name].get_pool_stats()
                health_stats = self.health_checks.get(db_name, {})
                
                stats[db_name] = {
                    'pool_stats': pool_stats,
                    'health_check': health_stats
                }
                
            except Exception as e:
                stats[db_name] = {
                    'error': str(e)
                }
        
        return stats
    
    def close_all(self):
        """Close all connection pools"""
        for db_name, pool in self.pools.items():
            try:
                pool.close()
                logger.info(f"Closed connection pool for database: {db_name}")
            except Exception as e:
                logger.error(f"Error closing pool for database {db_name}: {e}")
        
        # Close async pools
        for db_name, pool in self.async_pools.items():
            try:
                asyncio.run(pool.close())
                logger.info(f"Closed async connection pool for database: {db_name}")
            except Exception as e:
                logger.error(f"Error closing async pool for database {db_name}: {e}")

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create database configuration
    db_config = DatabaseConfig(
        host="localhost",
        port=5432,
        database="reports",
        username="reports_user",
        password="reports_password",
        pool_min_size=5,
        pool_max_size=20,
        pool_timeout=30,
        enable_metrics=True,
        metrics_namespace="reports_demo"
    )
    
    print("🔌 Database Connection Pooling Demo")
    print("=" * 50)
    
    # Initialize connection pool manager
    try:
        pool_manager = ConnectionPoolManager({"main": db_config})
        print("✅ Connection pool manager initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize connection pool manager: {e}")
        exit(1)
    
    # Test basic query execution
    print("\n1. Testing basic query execution...")
    try:
        # Simple health check query
        result = pool_manager.execute_query(
            "main", 
            "SELECT version() as db_version", 
            fetch_results=True
        )
        
        if result:
            print("✅ Basic query executed successfully")
            print(f"   Database version: {result[0]['db_version'][:50]}...")
        else:
            print("⚠️ Query executed but no results returned")
        
    except Exception as e:
        print(f"❌ Basic query execution failed: {e}")
    
    # Test transaction execution
    print("\n2. Testing transaction execution...")
    try:
        # Create test table
        queries = [
            ("CREATE TEMP TABLE test_table (id SERIAL PRIMARY KEY, name VARCHAR(50))", None),
            ("INSERT INTO test_table (name) VALUES (%s)", ("Alice",)),
            ("INSERT INTO test_table (name) VALUES (%s)", ("Bob",)),
            ("SELECT * FROM test_table ORDER BY id", None)
        ]
        
        results = pool_manager.execute_query("main", queries)
        
        if results:
            print("✅ Transaction executed successfully")
            print(f"   Inserted {len(results[3]) if results[3] else 0} records")
            if results[3]:
                for row in results[3][:3]:  # Show first 3 rows
                    print(f"   Row: {row}")
        else:
            print("⚠️ Transaction executed but no results returned")
        
    except Exception as e:
        print(f"❌ Transaction execution failed: {e}")
    
    # Test pool statistics
    print("\n3. Testing pool statistics...")
    try:
        stats = pool_manager.get_all_stats()
        print("✅ Pool statistics retrieved successfully")
        
        for db_name, db_stats in stats.items():
            if 'pool_stats' in db_stats:
                pool_stats = db_stats['pool_stats']
                print(f"   Database {db_name}:")
                print(f"     Pool status: {pool_stats.get('pool_status', 'N/A')}")
                print(f"     Queries executed: {pool_stats['metrics'].get('queries_executed', 0)}")
                print(f"     Queries failed: {pool_stats['metrics'].get('queries_failed', 0)}")
        
    except Exception as e:
        print(f"❌ Pool statistics retrieval failed: {e}")
    
    # Test health check
    print("\n4. Testing health check...")
    try:
        health = pool_manager.health_check("main")
        print("✅ Health check completed successfully")
        print(f"   Status: {health['status']}")
        print(f"   Latency: {health.get('latency_ms', 0):.2f}ms")
        
    except Exception as e:
        print(f"❌ Health check failed: {e}")
    
    # Cleanup
    pool_manager.close_all()
    
    print("\n🎯 Database Connection Pooling Demo Complete")
    print("This demonstrates the core functionality of the connection pooling system.")
    print("In a production environment, this would integrate with:")
    print("  • Multiple database instances for high availability")
    print("  • Connection pooling with advanced monitoring")
    print("  • Proper error handling and retry mechanisms")
    print("  • Security features like SSL/TLS encryption")
    print("  • Performance optimization with prepared statements")