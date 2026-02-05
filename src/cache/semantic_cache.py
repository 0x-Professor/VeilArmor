"""
VeilArmor v2.0 - Semantic Cache

Semantic similarity-based caching for LLM responses.
"""

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from src.cache.backends import BaseCacheBackend, MemoryCacheBackend
from src.cache.embeddings import (
    BaseEmbeddingProvider,
    SentenceTransformerProvider,
    HashEmbeddingProvider,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CacheEntry:
    """Semantic cache entry."""
    key: str
    query: str
    response: str
    embedding: List[float]
    created_at: float = field(default_factory=time.time)
    hit_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "key": self.key,
            "query": self.query,
            "response": self.response,
            "embedding": self.embedding,
            "created_at": self.created_at,
            "hit_count": self.hit_count,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CacheEntry":
        """Create from dictionary."""
        return cls(
            key=data["key"],
            query=data["query"],
            response=data["response"],
            embedding=data["embedding"],
            created_at=data.get("created_at", time.time()),
            hit_count=data.get("hit_count", 0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class CacheResult:
    """Result from cache lookup."""
    hit: bool
    entry: Optional[CacheEntry] = None
    similarity: float = 0.0
    lookup_time_ms: float = 0.0
    
    @property
    def response(self) -> Optional[str]:
        """Get cached response."""
        return self.entry.response if self.entry else None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hit": self.hit,
            "similarity": self.similarity,
            "lookup_time_ms": self.lookup_time_ms,
            "response": self.response,
        }


class SemanticCache:
    """
    Semantic similarity-based cache for LLM responses.
    
    Uses embeddings to find similar queries and return cached responses
    when similarity exceeds a threshold.
    
    Features:
    - Configurable similarity threshold
    - Multiple embedding providers
    - Redis or in-memory storage
    - Hit tracking and metrics
    """
    
    DEFAULT_SIMILARITY_THRESHOLD = 0.95
    
    def __init__(
        self,
        embedding_provider: Optional[BaseEmbeddingProvider] = None,
        cache_backend: Optional[BaseCacheBackend] = None,
        similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
        max_entries: int = 10000,
        default_ttl: int = 3600,
        index_prefix: str = "sem_idx:",
        entry_prefix: str = "sem_entry:",
    ):
        """
        Initialize semantic cache.
        
        Args:
            embedding_provider: Embedding provider
            cache_backend: Cache storage backend
            similarity_threshold: Minimum similarity for cache hit
            max_entries: Maximum cache entries
            default_ttl: Default TTL in seconds
            index_prefix: Prefix for index keys
            entry_prefix: Prefix for entry keys
        """
        self.similarity_threshold = similarity_threshold
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self.index_prefix = index_prefix
        self.entry_prefix = entry_prefix
        
        # Initialize embedding provider
        if embedding_provider is None:
            try:
                self.embedding_provider = SentenceTransformerProvider()
            except ImportError:
                logger.warning(
                    "sentence-transformers not available, using hash embeddings"
                )
                self.embedding_provider = HashEmbeddingProvider()
        else:
            self.embedding_provider = embedding_provider
        
        # Initialize cache backend
        if cache_backend is None:
            self.cache_backend = MemoryCacheBackend(
                max_size=max_entries,
                default_ttl=default_ttl,
            )
        else:
            self.cache_backend = cache_backend
        
        # In-memory index for fast similarity search
        self._embedding_index: Dict[str, np.ndarray] = {}
        self._lock = asyncio.Lock()
        
        # Metrics
        self._total_lookups = 0
        self._cache_hits = 0
        self._cache_misses = 0
        
        logger.info(
            "Semantic cache initialized",
            threshold=similarity_threshold,
            max_entries=max_entries,
            embedding_model=self.embedding_provider.model,
        )
    
    async def get(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> CacheResult:
        """
        Look up query in cache.
        
        Args:
            query: User query
            context: Optional context for lookup
            
        Returns:
            CacheResult
        """
        start_time = time.time()
        self._total_lookups += 1
        
        # Generate embedding for query
        result = await self.embedding_provider.embed(query)
        query_embedding = np.array(result.embedding, dtype=np.float32)
        
        # Find best match
        best_match = await self._find_best_match(query_embedding)
        
        lookup_time = (time.time() - start_time) * 1000
        
        if best_match is None:
            self._cache_misses += 1
            return CacheResult(
                hit=False,
                lookup_time_ms=lookup_time,
            )
        
        key, similarity = best_match
        
        if similarity < self.similarity_threshold:
            self._cache_misses += 1
            return CacheResult(
                hit=False,
                similarity=similarity,
                lookup_time_ms=lookup_time,
            )
        
        # Retrieve entry
        entry_data = await self.cache_backend.get(f"{self.entry_prefix}{key}")
        
        if entry_data is None:
            # Entry expired or missing
            self._cache_misses += 1
            async with self._lock:
                self._embedding_index.pop(key, None)
            return CacheResult(
                hit=False,
                lookup_time_ms=lookup_time,
            )
        
        entry = CacheEntry.from_dict(entry_data)
        entry.hit_count += 1
        
        # Update hit count
        await self.cache_backend.set(
            f"{self.entry_prefix}{key}",
            entry.to_dict(),
            ttl=self.default_ttl,
        )
        
        self._cache_hits += 1
        
        logger.debug(
            "Semantic cache hit",
            similarity=similarity,
            query_preview=query[:50],
        )
        
        return CacheResult(
            hit=True,
            entry=entry,
            similarity=similarity,
            lookup_time_ms=lookup_time,
        )
    
    async def set(
        self,
        query: str,
        response: str,
        ttl: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Store query-response pair in cache.
        
        Args:
            query: User query
            response: LLM response
            ttl: Optional TTL override
            metadata: Optional metadata
            
        Returns:
            Cache key
        """
        # Generate embedding
        result = await self.embedding_provider.embed(query)
        embedding = result.embedding
        
        # Generate key
        key = self._generate_key(query)
        
        # Create entry
        entry = CacheEntry(
            key=key,
            query=query,
            response=response,
            embedding=embedding,
            metadata=metadata or {},
        )
        
        # Store entry
        effective_ttl = ttl if ttl is not None else self.default_ttl
        await self.cache_backend.set(
            f"{self.entry_prefix}{key}",
            entry.to_dict(),
            ttl=effective_ttl,
        )
        
        # Add to index
        async with self._lock:
            # Evict if at capacity
            if len(self._embedding_index) >= self.max_entries:
                await self._evict_oldest()
            
            self._embedding_index[key] = np.array(embedding, dtype=np.float32)
        
        logger.debug(
            "Semantic cache set",
            key=key,
            query_preview=query[:50],
        )
        
        return key
    
    async def delete(self, key: str) -> bool:
        """
        Delete entry from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted
        """
        # Remove from backend
        deleted = await self.cache_backend.delete(f"{self.entry_prefix}{key}")
        
        # Remove from index
        async with self._lock:
            self._embedding_index.pop(key, None)
        
        return deleted
    
    async def clear(self) -> int:
        """
        Clear all cache entries.
        
        Returns:
            Number of entries cleared
        """
        # Get all entry keys
        keys = await self.cache_backend.keys(f"{self.entry_prefix}*")
        
        # Delete all
        count = await self.cache_backend.delete_many(keys)
        
        # Clear index
        async with self._lock:
            self._embedding_index.clear()
        
        logger.info("Semantic cache cleared", entries=count)
        
        return count
    
    async def _find_best_match(
        self,
        query_embedding: np.ndarray,
    ) -> Optional[Tuple[str, float]]:
        """Find best matching entry in index."""
        async with self._lock:
            if not self._embedding_index:
                return None
            
            best_key = None
            best_similarity = -1.0
            
            for key, embedding in self._embedding_index.items():
                similarity = float(np.dot(query_embedding, embedding))
                
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_key = key
            
            if best_key is None:
                return None
            
            return best_key, best_similarity
    
    async def _evict_oldest(self) -> None:
        """Evict oldest entry from cache."""
        if not self._embedding_index:
            return
        
        # Simple FIFO eviction - could be improved with LRU
        oldest_key = next(iter(self._embedding_index))
        
        # Remove from backend
        await self.cache_backend.delete(f"{self.entry_prefix}{oldest_key}")
        
        # Remove from index
        self._embedding_index.pop(oldest_key, None)
    
    def _generate_key(self, query: str) -> str:
        """Generate cache key from query."""
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:32]
        return f"{int(time.time() * 1000)}:{query_hash}"
    
    async def get_similar(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.5,
    ) -> List[Tuple[CacheEntry, float]]:
        """
        Find similar cached entries.
        
        Args:
            query: Query to match
            top_k: Maximum results
            min_similarity: Minimum similarity threshold
            
        Returns:
            List of (entry, similarity) tuples
        """
        # Generate embedding
        result = await self.embedding_provider.embed(query)
        query_embedding = np.array(result.embedding, dtype=np.float32)
        
        # Find matches
        matches = []
        
        async with self._lock:
            for key, embedding in self._embedding_index.items():
                similarity = float(np.dot(query_embedding, embedding))
                
                if similarity >= min_similarity:
                    matches.append((key, similarity))
        
        # Sort by similarity
        matches.sort(key=lambda x: x[1], reverse=True)
        matches = matches[:top_k]
        
        # Retrieve entries
        results = []
        for key, similarity in matches:
            entry_data = await self.cache_backend.get(f"{self.entry_prefix}{key}")
            if entry_data:
                entry = CacheEntry.from_dict(entry_data)
                results.append((entry, similarity))
        
        return results
    
    async def rebuild_index(self) -> int:
        """
        Rebuild embedding index from cache backend.
        
        Returns:
            Number of entries indexed
        """
        # Get all entry keys
        keys = await self.cache_backend.keys(f"{self.entry_prefix}*")
        
        async with self._lock:
            self._embedding_index.clear()
            
            count = 0
            for full_key in keys:
                entry_data = await self.cache_backend.get(full_key)
                if entry_data:
                    key = full_key.replace(self.entry_prefix, "")
                    self._embedding_index[key] = np.array(
                        entry_data["embedding"],
                        dtype=np.float32,
                    )
                    count += 1
        
        logger.info("Semantic cache index rebuilt", entries=count)
        
        return count
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get cache metrics."""
        return {
            "total_lookups": self._total_lookups,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "hit_rate": (
                self._cache_hits / self._total_lookups
                if self._total_lookups > 0
                else 0.0
            ),
            "index_size": len(self._embedding_index),
            "max_entries": self.max_entries,
            "similarity_threshold": self.similarity_threshold,
            "embedding_model": self.embedding_provider.model,
        }
    
    def reset_metrics(self) -> None:
        """Reset cache metrics."""
        self._total_lookups = 0
        self._cache_hits = 0
        self._cache_misses = 0
    
    async def close(self) -> None:
        """Close cache and release resources."""
        if hasattr(self.cache_backend, 'close'):
            await self.cache_backend.close()
        
        async with self._lock:
            self._embedding_index.clear()
