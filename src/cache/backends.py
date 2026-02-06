"""
VeilArmor - Cache Backends

Storage backends for caching with TTL support.
"""

import asyncio
import hashlib
import json
import pickle
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CacheItem:
    """Cache item with metadata."""
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        """Check if item is expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    @property
    def ttl(self) -> Optional[float]:
        """Get remaining TTL in seconds."""
        if self.expires_at is None:
            return None
        remaining = self.expires_at - time.time()
        return max(0, remaining)


class BaseCacheBackend(ABC):
    """Abstract base class for cache backends."""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Get value by key."""
        pass
    
    @abstractmethod
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Set value with optional TTL."""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete key."""
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        pass
    
    @abstractmethod
    async def clear(self) -> int:
        """Clear all keys. Returns count of deleted keys."""
        pass
    
    @abstractmethod
    async def keys(self, pattern: str = "*") -> List[str]:
        """Get keys matching pattern."""
        pass
    
    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values."""
        result = {}
        for key in keys:
            value = await self.get(key)
            if value is not None:
                result[key] = value
        return result
    
    async def set_many(
        self,
        items: Dict[str, Any],
        ttl: Optional[int] = None,
    ) -> int:
        """Set multiple values. Returns count of successful sets."""
        count = 0
        for key, value in items.items():
            if await self.set(key, value, ttl):
                count += 1
        return count
    
    async def delete_many(self, keys: List[str]) -> int:
        """Delete multiple keys. Returns count of deleted keys."""
        count = 0
        for key in keys:
            if await self.delete(key):
                count += 1
        return count


class MemoryCacheBackend(BaseCacheBackend):
    """
    In-memory cache backend for development and testing.
    
    Thread-safe with TTL support.
    """
    
    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: Optional[int] = 3600,
    ):
        """
        Initialize memory cache.
        
        Args:
            max_size: Maximum number of items
            default_ttl: Default TTL in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheItem] = {}
        self._lock = asyncio.Lock()
        
        logger.info(
            "Memory cache backend initialized",
            max_size=max_size,
            default_ttl=default_ttl,
        )
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value by key."""
        async with self._lock:
            item = self._cache.get(key)
            
            if item is None:
                return None
            
            if item.is_expired:
                del self._cache[key]
                return None
            
            return item.value
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Set value with optional TTL."""
        async with self._lock:
            # Evict if at max size
            if len(self._cache) >= self.max_size and key not in self._cache:
                await self._evict_expired()
                if len(self._cache) >= self.max_size:
                    await self._evict_oldest()
            
            # Calculate expiration
            effective_ttl = ttl if ttl is not None else self.default_ttl
            expires_at = None
            if effective_ttl is not None:
                expires_at = time.time() + effective_ttl
            
            self._cache[key] = CacheItem(
                key=key,
                value=value,
                expires_at=expires_at,
                metadata=metadata or {},
            )
            
            return True
    
    async def delete(self, key: str) -> bool:
        """Delete key."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        async with self._lock:
            item = self._cache.get(key)
            if item is None:
                return False
            if item.is_expired:
                del self._cache[key]
                return False
            return True
    
    async def clear(self) -> int:
        """Clear all keys."""
        async with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count
    
    async def keys(self, pattern: str = "*") -> List[str]:
        """Get keys matching pattern."""
        import fnmatch
        
        async with self._lock:
            result = []
            expired_keys = []
            
            for key, item in self._cache.items():
                if item.is_expired:
                    expired_keys.append(key)
                elif fnmatch.fnmatch(key, pattern):
                    result.append(key)
            
            # Clean expired
            for key in expired_keys:
                del self._cache[key]
            
            return result
    
    async def _evict_expired(self) -> int:
        """Evict expired items."""
        expired = [
            key for key, item in self._cache.items()
            if item.is_expired
        ]
        for key in expired:
            del self._cache[key]
        return len(expired)
    
    async def _evict_oldest(self) -> None:
        """Evict oldest item."""
        if not self._cache:
            return
        
        oldest_key = min(
            self._cache.keys(),
            key=lambda k: self._cache[k].created_at,
        )
        del self._cache[oldest_key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "default_ttl": self.default_ttl,
        }


class RedisCacheBackend(BaseCacheBackend):
    """
    Redis cache backend for production use.
    
    Features:
    - Connection pooling
    - Automatic reconnection
    - TTL support
    - JSON/Pickle serialization
    """
    
    def __init__(
        self,
        url: str = "redis://localhost:6379",
        db: int = 0,
        prefix: str = "veilarmor:",
        default_ttl: Optional[int] = 3600,
        max_connections: int = 10,
        serializer: str = "json",  # json or pickle
    ):
        """
        Initialize Redis cache.
        
        Args:
            url: Redis URL
            db: Database number
            prefix: Key prefix
            default_ttl: Default TTL in seconds
            max_connections: Max pool connections
            serializer: Serialization method
        """
        self.url = url
        self.db = db
        self.prefix = prefix
        self.default_ttl = default_ttl
        self.max_connections = max_connections
        self.serializer = serializer
        
        self._redis = None
        self._connected = False
        
        logger.info(
            "Redis cache backend initialized",
            url=url[:20] + "...",
            prefix=prefix,
            default_ttl=default_ttl,
        )
    
    async def _ensure_connected(self) -> None:
        """Ensure Redis connection is established."""
        if self._connected and self._redis:
            return
        
        try:
            import redis.asyncio as redis
            
            self._redis = redis.from_url(
                self.url,
                db=self.db,
                max_connections=self.max_connections,
                decode_responses=False,
            )
            
            # Test connection
            await self._redis.ping()
            self._connected = True
            
            logger.info("Redis connection established")
            
        except ImportError:
            logger.error("redis package not installed. Install with: pip install redis")
            raise ImportError("redis package required")
        except Exception as e:
            logger.error("Failed to connect to Redis", error=str(e))
            self._connected = False
            raise
    
    def _make_key(self, key: str) -> str:
        """Create prefixed key."""
        return f"{self.prefix}{key}"
    
    def _serialize(self, value: Any) -> bytes:
        """Serialize value."""
        if self.serializer == "json":
            try:
                return json.dumps(value).encode()
            except (TypeError, ValueError):
                # Fall back to pickle for non-JSON-serializable
                return pickle.dumps(value)
        else:
            return pickle.dumps(value)
    
    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value."""
        if self.serializer == "json":
            try:
                return json.loads(data.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Try pickle
                return pickle.loads(data)
        else:
            return pickle.loads(data)
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value by key."""
        await self._ensure_connected()
        
        try:
            data = await self._redis.get(self._make_key(key))
            if data is None:
                return None
            return self._deserialize(data)
        except Exception as e:
            logger.error("Redis get failed", key=key, error=str(e))
            return None
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Set value with optional TTL."""
        await self._ensure_connected()
        
        try:
            effective_ttl = ttl if ttl is not None else self.default_ttl
            data = self._serialize(value)
            
            if effective_ttl:
                await self._redis.setex(
                    self._make_key(key),
                    effective_ttl,
                    data,
                )
            else:
                await self._redis.set(self._make_key(key), data)
            
            # Store metadata if provided
            if metadata:
                meta_key = self._make_key(f"{key}:meta")
                meta_data = self._serialize(metadata)
                if effective_ttl:
                    await self._redis.setex(meta_key, effective_ttl, meta_data)
                else:
                    await self._redis.set(meta_key, meta_data)
            
            return True
            
        except Exception as e:
            logger.error("Redis set failed", key=key, error=str(e))
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key."""
        await self._ensure_connected()
        
        try:
            result = await self._redis.delete(self._make_key(key))
            # Also delete metadata
            await self._redis.delete(self._make_key(f"{key}:meta"))
            return result > 0
        except Exception as e:
            logger.error("Redis delete failed", key=key, error=str(e))
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists."""
        await self._ensure_connected()
        
        try:
            return await self._redis.exists(self._make_key(key)) > 0
        except Exception as e:
            logger.error("Redis exists failed", key=key, error=str(e))
            return False
    
    async def clear(self) -> int:
        """Clear all keys with prefix."""
        await self._ensure_connected()
        
        try:
            pattern = f"{self.prefix}*"
            keys = []
            
            async for key in self._redis.scan_iter(match=pattern):
                keys.append(key)
            
            if keys:
                return await self._redis.delete(*keys)
            return 0
            
        except Exception as e:
            logger.error("Redis clear failed", error=str(e))
            return 0
    
    async def keys(self, pattern: str = "*") -> List[str]:
        """Get keys matching pattern."""
        await self._ensure_connected()
        
        try:
            full_pattern = f"{self.prefix}{pattern}"
            result = []
            
            async for key in self._redis.scan_iter(match=full_pattern):
                # Remove prefix from key
                key_str = key.decode() if isinstance(key, bytes) else key
                if key_str.startswith(self.prefix):
                    result.append(key_str[len(self.prefix):])
            
            # Filter out metadata keys
            result = [k for k in result if not k.endswith(":meta")]
            
            return result
            
        except Exception as e:
            logger.error("Redis keys failed", pattern=pattern, error=str(e))
            return []
    
    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values efficiently."""
        await self._ensure_connected()
        
        try:
            if not keys:
                return {}
            
            full_keys = [self._make_key(k) for k in keys]
            values = await self._redis.mget(full_keys)
            
            result = {}
            for key, value in zip(keys, values):
                if value is not None:
                    result[key] = self._deserialize(value)
            
            return result
            
        except Exception as e:
            logger.error("Redis mget failed", error=str(e))
            return await super().get_many(keys)
    
    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._connected = False
            logger.info("Redis connection closed")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "connected": self._connected,
            "url": self.url[:20] + "...",
            "prefix": self.prefix,
            "default_ttl": self.default_ttl,
            "serializer": self.serializer,
        }
