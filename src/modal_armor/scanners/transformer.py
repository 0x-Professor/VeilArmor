"""
Transformer Scanner - ML-based prompt injection detection
"""

from typing import Dict, Any
import logging

from .base import BaseScanner

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False


class TransformerScanner(BaseScanner):
    """
    Uses transformer models to detect prompt injections using ML.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize Transformer scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        if not TRANSFORMERS_AVAILABLE:
            raise ImportError(
                "transformers is required. Install with: pip install transformers torch"
            )
        
        self.transformer_config = config.get('transformer', {})
        
        # Settings
        model_name = self.transformer_config.get(
            'model_name',
            'deepset/deberta-v3-base-injection'
        )
        self.threshold = self.transformer_config.get('threshold', 0.98)
        self.device = self.transformer_config.get('device', 'cpu')
        
        # Load model
        self.logger.info(f"Loading transformer model: {model_name}")
        self.classifier = pipeline(
            "text-classification",
            model=model_name,
            device=0 if self.device == 'cuda' else -1
        )
        
        self.logger.info("Transformer scanner initialized")
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text with transformer model.
        
        Args:
            text: Text to scan
            
        Returns:
            Scan result dictionary
        """
        try:
            # Truncate if too long
            max_length = self.transformer_config.get('max_length', 512)
            if len(text) > max_length * 4:  # Rough estimate
                text = text[:max_length * 4]
            
            # Run classifier
            result = self.classifier(text)[0]
            
            label = result['label']
            score = result['score']
            
            # Check if injection detected
            detected = (
                label.upper() in ['INJECTION', 'MALICIOUS', '1'] and
                score >= self.threshold
            )
            
            message = ""
            if detected:
                message = f"Transformer model detected injection (confidence: {score:.2%})"
            
            return self._create_result(
                detected=detected,
                score=score if detected else 0.0,
                message=message,
                label=label,
                threshold=self.threshold,
                model=self.transformer_config.get('model_name')
            )
            
        except Exception as e:
            self.logger.error(f"Transformer scan error: {e}")
            return self._create_result(detected=False, error=str(e))
