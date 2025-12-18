"""
Similarity Scanner - Detects prompt-response correlation issues
"""

from typing import Dict, Any
import logging

from .base import BaseScanner

try:
    from sentence_transformers import SentenceTransformer, util
    SBERT_AVAILABLE = True
except ImportError:
    SBERT_AVAILABLE = False


class SimilarityScanner(BaseScanner):
    """
    Analyzes similarity between prompt and response to detect goal hijacking.
    Low similarity may indicate the LLM's goal was hijacked.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize Similarity scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        if not SBERT_AVAILABLE:
            raise ImportError(
                "sentence-transformers required. Install with: pip install sentence-transformers"
            )
        
        self.similarity_config = config.get('similarity', {})
        
        # Settings
        self.threshold = self.similarity_config.get('threshold', 0.15)
        model_name = self.similarity_config.get('model', 'sentence-transformers/all-MiniLM-L6-v2')
        
        # Load model
        self.logger.info(f"Loading similarity model: {model_name}")
        self.model = SentenceTransformer(model_name)
        
        self.logger.info("Similarity scanner initialized")
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        This scanner requires both prompt and response.
        Use scan_similarity() instead.
        """
        return self._create_result(
            detected=False,
            message="Similarity scanner requires prompt and response"
        )
    
    def scan_similarity(self, prompt: str, response: str) -> Dict[str, Any]:
        """
        Scan similarity between prompt and response.
        
        Args:
            prompt: Original prompt
            response: LLM response
            
        Returns:
            Scan result dictionary
        """
        try:
            # Generate embeddings
            prompt_embedding = self.model.encode(prompt, convert_to_tensor=True)
            response_embedding = self.model.encode(response, convert_to_tensor=True)
            
            # Calculate cosine similarity
            similarity = util.cos_sim(prompt_embedding, response_embedding).item()
            
            # Low similarity indicates potential goal hijacking
            detected = similarity < self.threshold
            
            message = ""
            if detected:
                message = f"Low prompt-response similarity ({similarity:.2f}) indicates potential goal hijacking"
            
            return self._create_result(
                detected=detected,
                score=1.0 - similarity if detected else 0.0,
                message=message,
                similarity=similarity,
                threshold=self.threshold
            )
            
        except Exception as e:
            self.logger.error(f"Similarity scan error: {e}")
            return self._create_result(detected=False, error=str(e))
