"""
VeilArmor - Cache Module

Semantic caching with Redis and sentence-transformers.
"""

from src.cache.backends import (
    BaseCacheBackend,
    MemoryCacheBackend,
    RedisCacheBackend,
)
from src.cache.embeddings import (
    BaseEmbeddingProvider,
    SentenceTransformerProvider,
)
from src.cache.semantic_cache import (
    SemanticCache,
    CacheEntry,
    CacheResult,
)


__all__ = [
    # Backends
    "BaseCacheBackend",
    "MemoryCacheBackend",
    "RedisCacheBackend",
    # Embeddings
    "BaseEmbeddingProvider",
    "SentenceTransformerProvider",
    # Semantic cache
    "SemanticCache",
    "CacheEntry",
    "CacheResult",
]
