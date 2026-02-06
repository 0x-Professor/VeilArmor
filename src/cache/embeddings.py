"""
VeilArmor - Embedding Providers

Embedding providers for semantic similarity matching.
"""

import asyncio
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

import numpy as np

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EmbeddingResult:
    """Embedding result."""
    text: str
    embedding: List[float]
    model: str
    dimensions: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_numpy(self) -> np.ndarray:
        """Convert to numpy array."""
        return np.array(self.embedding, dtype=np.float32)


class BaseEmbeddingProvider(ABC):
    """Abstract base class for embedding providers."""
    
    def __init__(
        self,
        model: str,
        dimensions: int,
        normalize: bool = True,
    ):
        """
        Initialize embedding provider.
        
        Args:
            model: Model name
            dimensions: Embedding dimensions
            normalize: Normalize embeddings
        """
        self.model = model
        self.dimensions = dimensions
        self.normalize = normalize
    
    @abstractmethod
    async def embed(self, text: str) -> EmbeddingResult:
        """
        Generate embedding for text.
        
        Args:
            text: Text to embed
            
        Returns:
            EmbeddingResult
        """
        pass
    
    @abstractmethod
    async def embed_batch(
        self,
        texts: List[str],
    ) -> List[EmbeddingResult]:
        """
        Generate embeddings for multiple texts.
        
        Args:
            texts: List of texts
            
        Returns:
            List of EmbeddingResults
        """
        pass
    
    def cosine_similarity(
        self,
        embedding1: Union[List[float], np.ndarray],
        embedding2: Union[List[float], np.ndarray],
    ) -> float:
        """
        Calculate cosine similarity between embeddings.
        
        Args:
            embedding1: First embedding
            embedding2: Second embedding
            
        Returns:
            Similarity score (0-1)
        """
        vec1 = np.array(embedding1, dtype=np.float32)
        vec2 = np.array(embedding2, dtype=np.float32)
        
        # Normalize if not already
        if not self.normalize:
            vec1 = vec1 / (np.linalg.norm(vec1) + 1e-10)
            vec2 = vec2 / (np.linalg.norm(vec2) + 1e-10)
        
        return float(np.dot(vec1, vec2))
    
    def euclidean_distance(
        self,
        embedding1: Union[List[float], np.ndarray],
        embedding2: Union[List[float], np.ndarray],
    ) -> float:
        """
        Calculate Euclidean distance between embeddings.
        
        Args:
            embedding1: First embedding
            embedding2: Second embedding
            
        Returns:
            Distance score
        """
        vec1 = np.array(embedding1, dtype=np.float32)
        vec2 = np.array(embedding2, dtype=np.float32)
        
        return float(np.linalg.norm(vec1 - vec2))


class SentenceTransformerProvider(BaseEmbeddingProvider):
    """
    Embedding provider using sentence-transformers.
    
    Supports various models including:
    - all-MiniLM-L6-v2 (fast, 384 dims)
    - all-mpnet-base-v2 (accurate, 768 dims)
    - paraphrase-multilingual-MiniLM-L12-v2 (multilingual)
    """
    
    DEFAULT_MODEL = "all-MiniLM-L6-v2"
    
    MODEL_DIMENSIONS = {
        "all-MiniLM-L6-v2": 384,
        "all-MiniLM-L12-v2": 384,
        "all-mpnet-base-v2": 768,
        "paraphrase-MiniLM-L6-v2": 384,
        "paraphrase-multilingual-MiniLM-L12-v2": 384,
        "multi-qa-MiniLM-L6-cos-v1": 384,
    }
    
    def __init__(
        self,
        model: Optional[str] = None,
        device: Optional[str] = None,
        normalize: bool = True,
        batch_size: int = 32,
    ):
        """
        Initialize sentence transformer provider.
        
        Args:
            model: Model name
            device: Device (cpu, cuda)
            normalize: Normalize embeddings
            batch_size: Batch size for embedding
        """
        model = model or self.DEFAULT_MODEL
        dimensions = self.MODEL_DIMENSIONS.get(model, 384)
        
        super().__init__(
            model=model,
            dimensions=dimensions,
            normalize=normalize,
        )
        
        self.device = device
        self.batch_size = batch_size
        self._model = None
        self._initialized = False
    
    def _ensure_initialized(self) -> None:
        """Ensure model is loaded."""
        if self._initialized:
            return
        
        try:
            from sentence_transformers import SentenceTransformer
            
            self._model = SentenceTransformer(
                self.model,
                device=self.device,
            )
            
            self._initialized = True
            
            logger.info(
                "Sentence transformer initialized",
                model=self.model,
                dimensions=self.dimensions,
            )
            
        except ImportError:
            logger.error(
                "sentence-transformers not installed. "
                "Install with: pip install sentence-transformers"
            )
            raise ImportError("sentence-transformers package required")
    
    async def embed(self, text: str) -> EmbeddingResult:
        """
        Generate embedding for text.
        
        Args:
            text: Text to embed
            
        Returns:
            EmbeddingResult
        """
        self._ensure_initialized()
        
        # Run in thread pool
        loop = asyncio.get_event_loop()
        embedding = await loop.run_in_executor(
            None,
            lambda: self._model.encode(
                text,
                normalize_embeddings=self.normalize,
            ),
        )
        
        return EmbeddingResult(
            text=text,
            embedding=embedding.tolist(),
            model=self.model,
            dimensions=self.dimensions,
        )
    
    async def embed_batch(
        self,
        texts: List[str],
    ) -> List[EmbeddingResult]:
        """
        Generate embeddings for multiple texts.
        
        Args:
            texts: List of texts
            
        Returns:
            List of EmbeddingResults
        """
        self._ensure_initialized()
        
        # Run in thread pool
        loop = asyncio.get_event_loop()
        embeddings = await loop.run_in_executor(
            None,
            lambda: self._model.encode(
                texts,
                batch_size=self.batch_size,
                normalize_embeddings=self.normalize,
            ),
        )
        
        return [
            EmbeddingResult(
                text=text,
                embedding=embedding.tolist(),
                model=self.model,
                dimensions=self.dimensions,
            )
            for text, embedding in zip(texts, embeddings)
        ]
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        return {
            "model": self.model,
            "dimensions": self.dimensions,
            "normalize": self.normalize,
            "device": self.device or "auto",
            "initialized": self._initialized,
        }


class HashEmbeddingProvider(BaseEmbeddingProvider):
    """
    Simple hash-based embedding for testing and fallback.
    
    Uses consistent hashing to generate pseudo-embeddings.
    Not suitable for semantic similarity - use only for testing.
    """
    
    def __init__(
        self,
        dimensions: int = 384,
        normalize: bool = True,
    ):
        """
        Initialize hash embedding provider.
        
        Args:
            dimensions: Output dimensions
            normalize: Normalize embeddings
        """
        super().__init__(
            model="hash-embedding",
            dimensions=dimensions,
            normalize=normalize,
        )
    
    async def embed(self, text: str) -> EmbeddingResult:
        """Generate hash-based embedding."""
        embedding = self._hash_to_embedding(text)
        
        return EmbeddingResult(
            text=text,
            embedding=embedding,
            model=self.model,
            dimensions=self.dimensions,
            metadata={"type": "hash"},
        )
    
    async def embed_batch(
        self,
        texts: List[str],
    ) -> List[EmbeddingResult]:
        """Generate hash-based embeddings."""
        return [await self.embed(text) for text in texts]
    
    def _hash_to_embedding(self, text: str) -> List[float]:
        """Convert text to hash-based embedding."""
        # Create multiple hashes for dimensionality
        embeddings = []
        
        for i in range(self.dimensions // 32 + 1):
            hash_input = f"{text}:{i}".encode()
            hash_bytes = hashlib.sha256(hash_input).digest()
            
            # Convert bytes to floats
            for j in range(0, len(hash_bytes), 4):
                if len(embeddings) >= self.dimensions:
                    break
                value = int.from_bytes(hash_bytes[j:j+4], 'big')
                # Normalize to [-1, 1]
                normalized = (value / (2**32 - 1)) * 2 - 1
                embeddings.append(normalized)
        
        embeddings = embeddings[:self.dimensions]
        
        if self.normalize:
            norm = np.linalg.norm(embeddings)
            if norm > 0:
                embeddings = [e / norm for e in embeddings]
        
        return embeddings


class CachedEmbeddingProvider(BaseEmbeddingProvider):
    """
    Wrapper that adds caching to any embedding provider.
    """
    
    def __init__(
        self,
        provider: BaseEmbeddingProvider,
        cache_backend: Any,  # BaseCacheBackend
        ttl: int = 86400,  # 24 hours
        prefix: str = "emb:",
    ):
        """
        Initialize cached provider.
        
        Args:
            provider: Underlying embedding provider
            cache_backend: Cache backend
            ttl: Cache TTL in seconds
            prefix: Cache key prefix
        """
        super().__init__(
            model=provider.model,
            dimensions=provider.dimensions,
            normalize=provider.normalize,
        )
        
        self.provider = provider
        self.cache = cache_backend
        self.ttl = ttl
        self.prefix = prefix
        
        self._cache_hits = 0
        self._cache_misses = 0
    
    def _cache_key(self, text: str) -> str:
        """Generate cache key for text."""
        text_hash = hashlib.sha256(text.encode()).hexdigest()[:32]
        return f"{self.prefix}{self.model}:{text_hash}"
    
    async def embed(self, text: str) -> EmbeddingResult:
        """Generate embedding with caching."""
        cache_key = self._cache_key(text)
        
        # Check cache
        cached = await self.cache.get(cache_key)
        if cached is not None:
            self._cache_hits += 1
            return EmbeddingResult(
                text=text,
                embedding=cached["embedding"],
                model=self.model,
                dimensions=self.dimensions,
                metadata={"cached": True},
            )
        
        # Generate embedding
        self._cache_misses += 1
        result = await self.provider.embed(text)
        
        # Cache result
        await self.cache.set(
            cache_key,
            {"embedding": result.embedding},
            ttl=self.ttl,
        )
        
        return result
    
    async def embed_batch(
        self,
        texts: List[str],
    ) -> List[EmbeddingResult]:
        """Generate embeddings with caching."""
        # Check cache for all texts
        cache_keys = {text: self._cache_key(text) for text in texts}
        cached = await self.cache.get_many(list(cache_keys.values()))
        
        # Separate cached and uncached
        results = {}
        uncached_texts = []
        
        for text in texts:
            key = cache_keys[text]
            if key in cached:
                self._cache_hits += 1
                results[text] = EmbeddingResult(
                    text=text,
                    embedding=cached[key]["embedding"],
                    model=self.model,
                    dimensions=self.dimensions,
                    metadata={"cached": True},
                )
            else:
                self._cache_misses += 1
                uncached_texts.append(text)
        
        # Generate uncached embeddings
        if uncached_texts:
            new_results = await self.provider.embed_batch(uncached_texts)
            
            # Cache new results
            for result in new_results:
                key = cache_keys[result.text]
                await self.cache.set(
                    key,
                    {"embedding": result.embedding},
                    ttl=self.ttl,
                )
                results[result.text] = result
        
        # Return in original order
        return [results[text] for text in texts]
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total = self._cache_hits + self._cache_misses
        return {
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "hit_rate": self._cache_hits / total if total > 0 else 0.0,
        }
