"""
Redis Caching Architecture for Enterprise Reporting System
"""

import asyncio
import json
import pickle
import hashlib
import logging
from typing import Optional, Any, Dict, List, Union, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps
import time
import aioredis
from redis import Redis
from redis.cluster import RedisCluster
from redis.sentinel import Sentinel
import msgpack

logger = logging.getLogger(__name__)

@dataclass
class CacheConfig:
    """Redis Cache Configuration"""
    # Connection settings
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    ssl: bool = False
    timeout: int = 5
    
    # Connection pool settings
    max_connections: int = 20
    min_connections: int = 5
    connection_retry_attempts: int = 3
    connection_retry_delay: float = 1.0
    
    # Cache settings
    default_ttl_seconds: int = 3600  # 1 hour
    max_key_length: int = 250
    compression_threshold: int = 1024  # Compress values larger than 1KB
    enable_serialization: bool = True
    serialization_format: str = "msgpack"  # json, pickle, msgpack
    
    # Clustering settings
    enable_clustering: bool = False
    cluster_nodes: List[str] = None
    enable_sentinel: bool = False
    sentinel_master_name: str = "mymaster"
    sentinel_nodes: List[str] = None
    
    # Performance settings
    enable_pipeline: bool = True
    pipeline_batch_size: int = 100
    enable_local_cache: bool = True
    local_cache_max_size: int = 1000
    local_cache_ttl_seconds: int = 300  # 5 minutes
    
    # Security settings
    enable_encryption: bool = False
    encryption_key: Optional[str] = None
    
    # Monitoring settings
    enable_metrics: bool = True
    metrics_namespace: str = "reports_cache"
    slow_query_threshold_ms: int = 100

class CacheError(Exception):
    """Custom exception for cache errors"""
    pass

class RedisCacheManager:
    """Advanced Redis Cache Manager with clustering and sentinel support"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.redis_client = None
        self.local_cache = {} if config.enable_local_cache else None
        self.local_cache_access_times = {} if config.enable_local_cache else None
        self.metrics = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0,
            'errors': 0
        }
        self._initialize_redis_client()
    
    def _initialize_redis_client(self):
        """Initialize Redis client based on configuration"""
        try:
            if self.config.enable_clustering:
                # Redis Cluster mode
                startup_nodes = [
                    {"host": node.split(':')[0], "port": int(node.split(':')[1])}
                    for node in self.config.cluster_nodes or []
                ]
                self.redis_client = RedisCluster(
                    startup_nodes=startup_nodes,
                    password=self.config.password,
                    ssl=self.config.ssl,
                    socket_timeout=self.config.timeout,
                    max_connections=self.config.max_connections
                )
            elif self.config.enable_sentinel:
                # Redis Sentinel mode
                sentinel_nodes = [
                    (node.split(':')[0], int(node.split(':')[1]))
                    for node in self.config.sentinel_nodes or []
                ]
                sentinel = Sentinel(sentinel_nodes, socket_timeout=self.config.timeout)
                self.redis_client = sentinel.master_for(
                    self.config.sentinel_master_name,
                    socket_timeout=self.config.timeout,
                    password=self.config.password,
                    db=self.config.db
                )
            else:
                # Standalone Redis mode
                self.redis_client = Redis(
                    host=self.config.host,
                    port=self.config.port,
                    db=self.config.db,
                    password=self.config.password,
                    ssl=self.config.ssl,
                    socket_timeout=self.config.timeout,
                    max_connections=self.config.max_connections,
                    retry_on_timeout=True
                )
            
            # Test connection
            self.redis_client.ping()
            logger.info("Redis cache client initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing Redis client: {e}")
            raise CacheError(f"Redis initialization failed: {str(e)}")
    
    def _serialize_value(self, value: Any) -> bytes:
        """Serialize value for storage"""
        try:
            if self.config.serialization_format == "json":
                serialized = json.dumps(value, default=str).encode('utf-8')
            elif self.config.serialization_format == "pickle":
                serialized = pickle.dumps(value)
            elif self.config.serialization_format == "msgpack":
                serialized = msgpack.packb(value, default=str)
            else:
                # Default to pickle for unknown formats
                serialized = pickle.dumps(value)
            
            # Compress large values
            if len(serialized) > self.config.compression_threshold:
                import zlib
                compressed = zlib.compress(serialized)
                # Mark as compressed
                return b"COMPRESSED:" + compressed
            
            return serialized
            
        except Exception as e:
            logger.error(f"Error serializing value: {e}")
            raise CacheError(f"Serialization failed: {str(e)}")
    
    def _deserialize_value(self, serialized_value: bytes) -> Any:
        """Deserialize value from storage"""
        try:
            # Check if compressed
            if serialized_value.startswith(b"COMPRESSED:"):
                import zlib
                compressed_data = serialized_value[11:]  # Remove "COMPRESSED:" prefix
                serialized_value = zlib.decompress(compressed_data)
            
            if self.config.serialization_format == "json":
                return json.loads(serialized_value.decode('utf-8'))
            elif self.config.serialization_format == "pickle":
                return pickle.loads(serialized_value)
            elif self.config.serialization_format == "msgpack":
                return msgpack.unpackb(serialized_value, raw=False)
            else:
                # Default to pickle for unknown formats
                return pickle.loads(serialized_value)
                
        except Exception as e:
            logger.error(f"Error deserializing value: {e}")
            raise CacheError(f"Deserialization failed: {str(e)}")
    
    def _generate_cache_key(self, key: str, namespace: str = "") -> str:
        """Generate cache key with namespace and validation"""
        # Validate key length
        if len(key) > self.config.max_key_length:
            # Hash long keys
            key_hash = hashlib.sha256(key.encode('utf-8')).hexdigest()[:32]
            key = f"{key[:self.config.max_key_length-35]}_{key_hash}"
        
        # Add namespace if provided
        if namespace:
            key = f"{namespace}:{key}"
        
        return key
    
    def _update_metrics(self, operation: str, success: bool = True):
        """Update cache metrics"""
        if not self.config.enable_metrics:
            return
        
        try:
            if success:
                self.metrics[operation] = self.metrics.get(operation, 0) + 1
            else:
                self.metrics['errors'] = self.metrics.get('errors', 0) + 1
            
            # Update Redis metrics
            metric_key = f"{self.config.metrics_namespace}:metrics"
            self.redis_client.hincrby(metric_key, operation, 1)
            
        except Exception as e:
            logger.debug(f"Error updating metrics: {e}")
    
    def get(self, key: str, namespace: str = "", default: Any = None) -> Any:
        """Get value from cache"""
        try:
            start_time = time.time()
            
            # Generate full cache key
            cache_key = self._generate_cache_key(key, namespace)
            
            # Check local cache first
            if self.local_cache is not None:
                if cache_key in self.local_cache:
                    value, expiry = self.local_cache[cache_key]
                    if time.time() < expiry:
                        self._update_metrics('hits')
                        self._track_performance(start_time, "get_local_hit")
                        return value
                    else:
                        # Remove expired entry
                        del self.local_cache[cache_key]
                        if cache_key in self.local_cache_access_times:
                            del self.local_cache_access_times[cache_key]
            
            # Get from Redis
            serialized_value = self.redis_client.get(cache_key)
            
            if serialized_value is None:
                self._update_metrics('misses')
                self._track_performance(start_time, "get_miss")
                return default
            
            # Deserialize value
            value = self._deserialize_value(serialized_value)
            
            # Update local cache
            if self.local_cache is not None:
                expiry = time.time() + self.config.local_cache_ttl_seconds
                self.local_cache[cache_key] = (value, expiry)
                self.local_cache_access_times[cache_key] = time.time()
                
                # Clean up local cache if too large
                self._cleanup_local_cache()
            
            self._update_metrics('hits')
            self._track_performance(start_time, "get_hit")
            return value
            
        except Exception as e:
            logger.error(f"Error getting cache key {key}: {e}")
            self._update_metrics('errors')
            return default
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None, 
            namespace: str = "") -> bool:
        """Set value in cache"""
        try:
            start_time = time.time()
            
            # Generate full cache key
            cache_key = self._generate_cache_key(key, namespace)
            
            # Serialize value
            serialized_value = self._serialize_value(value)
            
            # Set expiration time
            expiration = ttl if ttl is not None else self.config.default_ttl_seconds
            
            # Set in Redis
            result = self.redis_client.setex(cache_key, expiration, serialized_value)
            
            # Update local cache
            if self.local_cache is not None and result:
                expiry = time.time() + (expiration or self.config.local_cache_ttl_seconds)
                self.local_cache[cache_key] = (value, expiry)
                self.local_cache_access_times[cache_key] = time.time()
                
                # Clean up local cache if too large
                self._cleanup_local_cache()
            
            if result:
                self._update_metrics('sets')
                self._track_performance(start_time, "set_success")
            else:
                self._update_metrics('errors')
                self._track_performance(start_time, "set_failure")
            
            return bool(result)
            
        except Exception as e:
            logger.error(f"Error setting cache key {key}: {e}")
            self._update_metrics('errors')
            return False
    
    def delete(self, key: str, namespace: str = "") -> bool:
        """Delete value from cache"""
        try:
            start_time = time.time()
            
            # Generate full cache key
            cache_key = self._generate_cache_key(key, namespace)
            
            # Delete from Redis
            result = self.redis_client.delete(cache_key)
            
            # Delete from local cache
            if self.local_cache is not None:
                if cache_key in self.local_cache:
                    del self.local_cache[cache_key]
                if cache_key in self.local_cache_access_times:
                    del self.local_cache_access_times[cache_key]
            
            if result:
                self._update_metrics('deletes')
                self._track_performance(start_time, "delete_success")
            else:
                self._track_performance(start_time, "delete_not_found")
            
            return bool(result)
            
        except Exception as e:
            logger.error(f"Error deleting cache key {key}: {e}")
            self._update_metrics('errors')
            return False
    
    def exists(self, key: str, namespace: str = "") -> bool:
        """Check if key exists in cache"""
        try:
            cache_key = self._generate_cache_key(key, namespace)
            
            # Check local cache first
            if self.local_cache is not None:
                if cache_key in self.local_cache:
                    _, expiry = self.local_cache[cache_key]
                    if time.time() < expiry:
                        return True
                    else:
                        # Remove expired entry
                        del self.local_cache[cache_key]
                        if cache_key in self.local_cache_access_times:
                            del self.local_cache_access_times[cache_key]
            
            # Check Redis
            return bool(self.redis_client.exists(cache_key))
            
        except Exception as e:
            logger.error(f"Error checking existence of cache key {key}: {e}")
            self._update_metrics('errors')
            return False
    
    def expire(self, key: str, ttl: int, namespace: str = "") -> bool:
        """Set expiration time for key"""
        try:
            cache_key = self._generate_cache_key(key, namespace)
            
            # Update Redis expiration
            result = self.redis_client.expire(cache_key, ttl)
            
            # Update local cache expiration
            if self.local_cache is not None and cache_key in self.local_cache:
                value, _ = self.local_cache[cache_key]
                expiry = time.time() + ttl
                self.local_cache[cache_key] = (value, expiry)
            
            return bool(result)
            
        except Exception as e:
            logger.error(f"Error setting expiration for cache key {key}: {e}")
            self._update_metrics('errors')
            return False
    
    def incr(self, key: str, amount: int = 1, namespace: str = "") -> Optional[int]:
        """Increment integer value in cache"""
        try:
            cache_key = self._generate_cache_key(key, namespace)
            
            # Increment in Redis
            result = self.redis_client.incrby(cache_key, amount)
            
            # Update local cache
            if self.local_cache is not None:
                if cache_key in self.local_cache:
                    current_value, expiry = self.local_cache[cache_key]
                    if isinstance(current_value, int):
                        self.local_cache[cache_key] = (current_value + amount, expiry)
            
            return result
            
        except Exception as e:
            logger.error(f"Error incrementing cache key {key}: {e}")
            self._update_metrics('errors')
            return None
    
    def flush(self, pattern: str = "*", namespace: str = "") -> bool:
        """Flush cache entries matching pattern"""
        try:
            if namespace:
                pattern = f"{namespace}:{pattern}"
            
            # Get all matching keys
            keys = self.redis_client.keys(pattern)
            
            if keys:
                # Delete all matching keys
                self.redis_client.delete(*keys)
            
            # Clear local cache
            if self.local_cache is not None:
                if pattern == "*":
                    self.local_cache.clear()
                    if self.local_cache_access_times is not None:
                        self.local_cache_access_times.clear()
                else:
                    # Clear matching entries from local cache
                    keys_to_delete = []
                    for cache_key in self.local_cache:
                        if pattern.replace("*", "") in cache_key:
                            keys_to_delete.append(cache_key)
                    
                    for cache_key in keys_to_delete:
                        del self.local_cache[cache_key]
                        if self.local_cache_access_times is not None:
                            if cache_key in self.local_cache_access_times:
                                del self.local_cache_access_times[cache_key]
            
            logger.info(f"Flushed {len(keys)} cache entries matching pattern: {pattern}")
            return True
            
        except Exception as e:
            logger.error(f"Error flushing cache with pattern {pattern}: {e}")
            self._update_metrics('errors')
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            # Get Redis info
            redis_info = self.redis_client.info()
            
            # Get memory usage
            memory_info = {
                'used_memory': redis_info.get('used_memory_human', 'N/A'),
                'used_memory_rss': redis_info.get('used_memory_rss_human', 'N/A'),
                'used_memory_peak': redis_info.get('used_memory_peak_human', 'N/A'),
                'mem_fragmentation_ratio': redis_info.get('mem_fragmentation_ratio', 'N/A')
            }
            
            # Get key statistics
            key_info = {
                'total_commands_processed': redis_info.get('total_commands_processed', 0),
                'expired_keys': redis_info.get('expired_keys', 0),
                'evicted_keys': redis_info.get('evicted_keys', 0),
                'keyspace_hits': redis_info.get('keyspace_hits', 0),
                'keyspace_misses': redis_info.get('keyspace_misses', 0)
            }
            
            # Calculate hit ratio
            hits = key_info['keyspace_hits']
            misses = key_info['keyspace_misses']
            hit_ratio = hits / (hits + misses) if (hits + misses) > 0 else 0
            
            return {
                'memory': memory_info,
                'keys': key_info,
                'hit_ratio': round(hit_ratio, 4),
                'metrics': self.metrics.copy(),
                'local_cache_size': len(self.local_cache) if self.local_cache else 0,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting cache statistics: {e}")
            return {
                'error': str(e),
                'metrics': self.metrics.copy()
            }
    
    def _cleanup_local_cache(self):
        """Clean up local cache when it exceeds size limit"""
        if self.local_cache is None:
            return
        
        if len(self.local_cache) > self.config.local_cache_max_size:
            # Remove oldest entries
            oldest_entries = sorted(
                self.local_cache_access_times.items(),
                key=lambda x: x[1]
            )[:50]  # Remove 50 oldest entries
            
            for cache_key, _ in oldest_entries:
                if cache_key in self.local_cache:
                    del self.local_cache[cache_key]
                del self.local_cache_access_times[cache_key]
            
            logger.debug(f"Cleaned up local cache, removed {len(oldest_entries)} entries")
    
    def _track_performance(self, start_time: float, operation: str):
        """Track performance metrics"""
        if not self.config.enable_metrics:
            return
        
        duration_ms = (time.time() - start_time) * 1000
        
        # Log slow queries
        if duration_ms > self.config.slow_query_threshold_ms:
            logger.warning(f"Slow cache operation: {operation} took {duration_ms:.2f}ms")
        
        # Update performance metrics in Redis
        try:
            metric_key = f"{self.config.metrics_namespace}:performance:{operation}"
            self.redis_client.lpush(metric_key, duration_ms)
            self.redis_client.ltrim(metric_key, 0, 999)  # Keep last 1000 measurements
        except Exception as e:
            logger.debug(f"Error tracking performance metrics: {e}")
    
    def pipeline(self):
        """Create Redis pipeline for batch operations"""
        return self.redis_client.pipeline()
    
    def batch_get(self, keys: List[str], namespace: str = "") -> Dict[str, Any]:
        """Batch get multiple keys"""
        try:
            start_time = time.time()
            
            # Generate full cache keys
            cache_keys = [self._generate_cache_key(key, namespace) for key in keys]
            
            # Pipeline batch get
            pipe = self.redis_client.pipeline()
            for cache_key in cache_keys:
                pipe.get(cache_key)
            
            results = pipe.execute()
            
            # Process results
            batch_results = {}
            for i, (key, serialized_value) in enumerate(zip(keys, results)):
                if serialized_value is not None:
                    try:
                        value = self._deserialize_value(serialized_value)
                        batch_results[key] = value
                        
                        # Update local cache
                        if self.local_cache is not None:
                            cache_key = cache_keys[i]
                            expiry = time.time() + self.config.local_cache_ttl_seconds
                            self.local_cache[cache_key] = (value, expiry)
                            self.local_cache_access_times[cache_key] = time.time()
                    except Exception as e:
                        logger.error(f"Error deserializing value for key {key}: {e}")
                        batch_results[key] = None
                else:
                    batch_results[key] = None
            
            self._track_performance(start_time, "batch_get")
            return batch_results
            
        except Exception as e:
            logger.error(f"Error in batch get operation: {e}")
            self._update_metrics('errors')
            return {key: None for key in keys}
    
    def batch_set(self, items: Dict[str, Any], ttl: Optional[int] = None, 
                  namespace: str = "") -> bool:
        """Batch set multiple key-value pairs"""
        try:
            start_time = time.time()
            
            # Pipeline batch set
            pipe = self.redis_client.pipeline()
            
            for key, value in items.items():
                try:
                    cache_key = self._generate_cache_key(key, namespace)
                    serialized_value = self._serialize_value(value)
                    expiration = ttl if ttl is not None else self.config.default_ttl_seconds
                    
                    pipe.setex(cache_key, expiration, serialized_value)
                    
                    # Update local cache
                    if self.local_cache is not None:
                        expiry = time.time() + (expiration or self.config.local_cache_ttl_seconds)
                        self.local_cache[cache_key] = (value, expiry)
                        self.local_cache_access_times[cache_key] = time.time()
                        
                except Exception as e:
                    logger.error(f"Error serializing value for key {key}: {e}")
                    continue
            
            # Execute pipeline
            pipe.execute()
            
            self._track_performance(start_time, "batch_set")
            self._update_metrics('sets')
            return True
            
        except Exception as e:
            logger.error(f"Error in batch set operation: {e}")
            self._update_metrics('errors')
            return False
    
    def close(self):
        """Close Redis connection"""
        try:
            if self.redis_client:
                self.redis_client.close()
            logger.info("Redis cache connection closed")
        except Exception as e:
            logger.error(f"Error closing Redis connection: {e}")

class CachedDataManager:
    """High-level cached data manager with business logic"""
    
    def __init__(self, cache_manager: RedisCacheManager):
        self.cache_manager = cache_manager
        self.logger = logging.getLogger(__name__)
    
    def cache_method(self, ttl: Optional[int] = None, namespace: str = "methods", 
                     key_generator: Optional[Callable] = None):
        """Decorator to cache method results"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Generate cache key
                if key_generator:
                    cache_key = key_generator(*args, **kwargs)
                else:
                    # Default key generation based on function name and arguments
                    import hashlib
                    arg_str = str(args) + str(sorted(kwargs.items()))
                    cache_key = f"{func.__name__}:{hashlib.md5(arg_str.encode()).hexdigest()}"
                
                # Try to get from cache
                cached_result = self.cache_manager.get(cache_key, namespace)
                if cached_result is not None:
                    self.logger.debug(f"Cache hit for {cache_key}")
                    return cached_result
                
                # Execute function and cache result
                try:
                    result = func(*args, **kwargs)
                    self.cache_manager.set(cache_key, result, ttl, namespace)
                    self.logger.debug(f"Cache miss for {cache_key}, result cached")
                    return result
                except Exception as e:
                    self.logger.error(f"Error executing cached method {func.__name__}: {e}")
                    # Return result even if caching fails
                    return result
            
            return wrapper
        return decorator
    
    def cache_report_data(self, report_type: str, hostname: str, 
                         data: Any, ttl: Optional[int] = None) -> bool:
        """Cache report data with specific key structure"""
        try:
            cache_key = f"report:{report_type}:{hostname}"
            return self.cache_manager.set(
                cache_key, data, ttl or 3600, "reports"
            )
        except Exception as e:
            self.logger.error(f"Error caching report data: {e}")
            return False
    
    def get_cached_report_data(self, report_type: str, hostname: str) -> Optional[Any]:
        """Get cached report data"""
        try:
            cache_key = f"report:{report_type}:{hostname}"
            return self.cache_manager.get(cache_key, "reports")
        except Exception as e:
            self.logger.error(f"Error getting cached report data: {e}")
            return None
    
    def invalidate_report_cache(self, report_type: str = None, hostname: str = None) -> bool:
        """Invalidate report cache entries"""
        try:
            if report_type and hostname:
                cache_key = f"report:{report_type}:{hostname}"
                return self.cache_manager.delete(cache_key, "reports")
            elif report_type:
                pattern = f"report:{report_type}:*"
                return self.cache_manager.flush(pattern, "reports")
            elif hostname:
                pattern = f"report:*:{hostname}"
                return self.cache_manager.flush(pattern, "reports")
            else:
                # Flush all report cache
                return self.cache_manager.flush("report:*", "reports")
        except Exception as e:
            self.logger.error(f"Error invalidating report cache: {e}")
            return False
    
    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        try:
            # Get basic cache stats
            cache_stats = self.cache_manager.get_stats()
            
            # Add business-specific metrics
            business_stats = {
                'report_cache_entries': self._count_report_cache_entries(),
                'active_sessions': self._count_active_sessions(),
                'popular_reports': self._get_popular_reports()
            }
            
            return {
                **cache_stats,
                **business_stats,
                'business_metrics': True
            }
            
        except Exception as e:
            self.logger.error(f"Error getting cache statistics: {e}")
            return {'error': str(e)}
    
    def _count_report_cache_entries(self) -> int:
        """Count report cache entries"""
        try:
            report_keys = self.cache_manager.redis_client.keys("reports:report:*")
            return len(report_keys)
        except Exception:
            return 0
    
    def _count_active_sessions(self) -> int:
        """Count active user sessions"""
        try:
            session_keys = self.cache_manager.redis_client.keys("sessions:*")
            return len(session_keys)
        except Exception:
            return 0
    
    def _get_popular_reports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most frequently accessed reports"""
        try:
            # This would require tracking access patterns
            # For now, return placeholder data
            return [
                {'report_type': 'system', 'access_count': 1500},
                {'report_type': 'network', 'access_count': 1200},
                {'report_type': 'filesystem', 'access_count': 800}
            ]
        except Exception:
            return []

# Async version of Redis cache manager for high-performance applications
class AsyncRedisCacheManager:
    """Async Redis Cache Manager for high-performance applications"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.redis_client = None
        self.local_cache = {} if config.enable_local_cache else None
        self.metrics = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0,
            'errors': 0
        }
        self._initialize_async_client()
    
    def _initialize_async_client(self):
        """Initialize async Redis client"""
        try:
            # For async, we'll use aioredis
            redis_url = f"redis://{self.config.host}:{self.config.port}/{self.config.db}"
            if self.config.password:
                redis_url = f"redis://:{self.config.password}@{self.config.host}:{self.config.port}/{self.config.db}"
            
            # Note: In a real implementation, you'd initialize the async client properly
            # This is a simplified example for demonstration purposes
            
        except Exception as e:
            logger.error(f"Error initializing async Redis client: {e}")
    
    async def get(self, key: str, namespace: str = "", default: Any = None) -> Any:
        """Async get value from cache"""
        # Implementation would be similar to sync version but with await calls
        pass
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None, 
                  namespace: str = "") -> bool:
        """Async set value in cache"""
        # Implementation would be similar to sync version but with await calls
        pass

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create cache configuration
    cache_config = CacheConfig(
        host="localhost",
        port=6379,
        enable_local_cache=True,
        local_cache_max_size=1000,
        enable_metrics=True,
        metrics_namespace="reports_demo"
    )
    
    print("🚀 Redis Caching Architecture Demo")
    print("=" * 50)
    
    # Initialize cache manager
    try:
        cache_manager = RedisCacheManager(cache_config)
        print("✅ Cache manager initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize cache manager: {e}")
        exit(1)
    
    # Test basic cache operations
    print("\n1. Testing basic cache operations...")
    try:
        # Set values
        cache_manager.set("test_key", "Hello, World!", ttl=60)
        cache_manager.set("test_number", 42, ttl=60)
        cache_manager.set("test_dict", {"name": "John", "age": 30}, ttl=60)
        
        # Get values
        test_value = cache_manager.get("test_key")
        test_number = cache_manager.get("test_number")
        test_dict = cache_manager.get("test_dict")
        
        print(f"✅ Retrieved values:")
        print(f"   String: {test_value}")
        print(f"   Number: {test_number}")
        print(f"   Dict: {test_dict}")
        
        # Test cache hit/miss
        cache_manager.get("nonexistent_key")  # This should be a miss
        
    except Exception as e:
        print(f"❌ Basic cache operations failed: {e}")
    
    # Test batch operations
    print("\n2. Testing batch operations...")
    try:
        # Batch set
        batch_data = {
            "user_1": {"name": "Alice", "email": "alice@example.com"},
            "user_2": {"name": "Bob", "email": "bob@example.com"},
            "user_3": {"name": "Charlie", "email": "charlie@example.com"}
        }
        
        cache_manager.batch_set(batch_data, ttl=300)
        print("✅ Batch set completed")
        
        # Batch get
        user_keys = ["user_1", "user_2", "user_3", "user_4"]  # user_4 doesn't exist
        batch_results = cache_manager.batch_get(user_keys)
        
        print("✅ Batch get results:")
        for key, value in batch_results.items():
            print(f"   {key}: {value}")
        
    except Exception as e:
        print(f"❌ Batch operations failed: {e}")
    
    # Test cache statistics
    print("\n3. Testing cache statistics...")
    try:
        stats = cache_manager.get_stats()
        print("✅ Cache statistics:")
        print(f"   Hits: {stats.get('metrics', {}).get('hits', 0)}")
        print(f"   Misses: {stats.get('metrics', {}).get('misses', 0)}")
        print(f"   Hit Ratio: {stats.get('hit_ratio', 0):.2%}")
        
    except Exception as e:
        print(f"❌ Cache statistics failed: {e}")
    
    # Test cached data manager
    print("\n4. Testing cached data manager...")
    try:
        data_manager = CachedDataManager(cache_manager)
        
        # Cache report data
        report_data = {
            "cpu_usage": 45.2,
            "memory_usage": 67.8,
            "disk_usage": 82.1,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        success = data_manager.cache_report_data("system", "server01", report_data)
        if success:
            print("✅ Report data cached successfully")
            
            # Retrieve cached report data
            cached_report = data_manager.get_cached_report_data("system", "server01")
            print(f"✅ Retrieved cached report: {cached_report}")
        else:
            print("❌ Failed to cache report data")
        
    except Exception as e:
        print(f"❌ Cached data manager test failed: {e}")
    
    # Cleanup
    cache_manager.close()
    
    print("\n🎯 Redis Caching Architecture Demo Complete")
    print("This demonstrates the core functionality of the Redis caching system.")
    print("In a production environment, this would integrate with:")
    print("  • Redis Cluster for high availability")
    print("  • Redis Sentinel for automatic failover")
    print("  • Connection pooling for efficient resource usage")
    print("  • Advanced monitoring and alerting")
    print("  • Proper error handling and logging")
    print("  • Security features like authentication and encryption")