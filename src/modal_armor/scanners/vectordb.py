"""
Vector Database Scanner - Uses similarity search to detect known attack patterns
"""

from typing import Dict, Any, List
import logging
from pathlib import Path

from .base import BaseScanner

try:
    import chromadb
    from sentence_transformers import SentenceTransformer
    CHROMA_AVAILABLE = True
except ImportError:
    CHROMA_AVAILABLE = False


class VectorDBScanner(BaseScanner):
    """
    Scans prompts against a vector database of known attack patterns.
    Uses semantic similarity to detect variations of known attacks.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize Vector DB scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        if not CHROMA_AVAILABLE:
            raise ImportError(
                "chromadb and sentence-transformers are required for VectorDB scanner. "
                "Install with: pip install chromadb sentence-transformers"
            )
        
        self.vectordb_config = config.get('vectordb', {})
        
        # Settings
        self.similarity_threshold = self.vectordb_config.get('similarity_threshold', 0.85)
        self.top_k = self.vectordb_config.get('top_k', 5)
        self.auto_update = self.vectordb_config.get('auto_update_enabled', False)
        self.auto_update_threshold = self.vectordb_config.get('auto_update_threshold', 0.95)
        
        # Initialize embedding model
        model_name = self.vectordb_config.get('embedding_model', 'sentence-transformers/all-MiniLM-L6-v2')
        self.logger.info(f"Loading embedding model: {model_name}")
        
        if 'text-embedding' in model_name:
            # OpenAI embeddings
            self.use_openai = True
            self._init_openai()
        else:
            # Local embeddings
            self.use_openai = False
            self.model = SentenceTransformer(model_name)
        
        # Initialize ChromaDB
        self._init_chromadb()
        
        self.logger.info("VectorDB scanner initialized")
    
    def _init_openai(self) -> None:
        """Initialize OpenAI client for embeddings"""
        try:
            import openai
            import os
            
            api_key = os.getenv('OPENAI_API_KEY') or self.config.get('openai', {}).get('api_key')
            if not api_key:
                raise ValueError("OPENAI_API_KEY not found in environment or config")
            
            self.openai_client = openai.OpenAI(api_key=api_key)
            self.embedding_model = self.vectordb_config.get('embedding_model', 'text-embedding-ada-002')
            self.logger.info(f"OpenAI embeddings initialized: {self.embedding_model}")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize OpenAI: {e}")
    
    def _init_chromadb(self) -> None:
        """Initialize ChromaDB client and collection"""
        db_path = self.vectordb_config.get('path', 'data/vectordb')
        Path(db_path).mkdir(parents=True, exist_ok=True)
        
        self.client = chromadb.PersistentClient(path=db_path)
        
        collection_name = self.vectordb_config.get('collection_name', 'modal_armor_threats')
        
        # Get or create collection
        try:
            self.collection = self.client.get_collection(name=collection_name)
            self.logger.info(f"Loaded existing collection: {collection_name}")
        except:
            self.collection = self.client.create_collection(
                name=collection_name,
                metadata={"description": "Modal Armor threat patterns"}
            )
            self.logger.info(f"Created new collection: {collection_name}")
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text against vector database.
        
        Args:
            text: Text to scan
            
        Returns:
            Scan result dictionary
        """
        try:
            # Generate embedding
            embedding = self._get_embedding(text)
            
            # Query collection
            results = self.collection.query(
                query_embeddings=[embedding],
                n_results=self.top_k
            )
            
            # Check if any matches exceed threshold
            matches = []
            detected = False
            max_score = 0.0
            
            if results['distances'] and len(results['distances'][0]) > 0:
                for i, distance in enumerate(results['distances'][0]):
                    # Convert distance to similarity (1 - distance for cosine)
                    similarity = 1.0 - distance
                    
                    if similarity >= self.similarity_threshold:
                        detected = True
                        max_score = max(max_score, similarity)
                        
                        match = {
                            'text': results['documents'][0][i] if results['documents'] else None,
                            'similarity': similarity,
                            'distance': distance,
                            'metadata': results['metadatas'][0][i] if results['metadatas'] else None
                        }
                        matches.append(match)
            
            # Auto-update database if high confidence detection
            if detected and self.auto_update and max_score >= self.auto_update_threshold:
                self._add_to_database(text, {'detected': True, 'score': max_score})
            
            message = ""
            if detected:
                message = f"Similar to known attack pattern (similarity: {max_score:.2f})"
            
            return self._create_result(
                detected=detected,
                score=max_score,
                message=message,
                matches=matches,
                threshold=self.similarity_threshold
            )
            
        except Exception as e:
            self.logger.error(f"VectorDB scan error: {e}")
            return self._create_result(detected=False, error=str(e))
    
    def _get_embedding(self, text: str) -> List[float]:
        """
        Generate embedding for text.
        
        Args:
            text: Text to embed
            
        Returns:
            Embedding vector
        """
        if self.use_openai:
            response = self.openai_client.embeddings.create(
                input=text,
                model=self.embedding_model
            )
            return response.data[0].embedding
        else:
            return self.model.encode(text).tolist()
    
    def _add_to_database(self, text: str, metadata: Dict[str, Any]) -> None:
        """
        Add new threat pattern to database.
        
        Args:
            text: Threat text to add
            metadata: Metadata about the threat
        """
        try:
            embedding = self._get_embedding(text)
            
            # Generate unique ID
            import hashlib
            text_id = hashlib.sha256(text.encode()).hexdigest()[:16]
            
            self.collection.add(
                embeddings=[embedding],
                documents=[text],
                metadatas=[metadata],
                ids=[text_id]
            )
            
            self.logger.info(f"Added new threat pattern to database: {text[:50]}...")
        except Exception as e:
            self.logger.error(f"Failed to add to database: {e}")
    
    def add_patterns(self, patterns: List[str], metadata: List[Dict[str, Any]] = None) -> int:
        """
        Bulk add threat patterns to database.
        
        Args:
            patterns: List of threat patterns
            metadata: Optional list of metadata dictionaries
            
        Returns:
            Number of patterns added
        """
        if not patterns:
            return 0
        
        if metadata is None:
            metadata = [{}] * len(patterns)
        
        try:
            embeddings = [self._get_embedding(p) for p in patterns]
            
            import hashlib
            ids = [hashlib.sha256(p.encode()).hexdigest()[:16] for p in patterns]
            
            self.collection.add(
                embeddings=embeddings,
                documents=patterns,
                metadatas=metadata,
                ids=ids
            )
            
            self.logger.info(f"Added {len(patterns)} patterns to database")
            return len(patterns)
            
        except Exception as e:
            self.logger.error(f"Failed to bulk add patterns: {e}")
            return 0
