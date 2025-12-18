"""
Sentiment Scanner - Detects suspicious emotional manipulation
"""

from typing import Dict, Any
import logging

from .base import BaseScanner

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False


class SentimentScanner(BaseScanner):
    """
    Analyzes sentiment to detect emotional manipulation attempts.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize Sentiment scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        super().__init__(config, logger)
        
        if not TRANSFORMERS_AVAILABLE:
            raise ImportError(
                "transformers required. Install with: pip install transformers"
            )
        
        self.sentiment_config = config.get('sentiment', {})
        
        # Settings
        self.threshold = self.sentiment_config.get('suspicious_threshold', 0.85)
        model_name = self.sentiment_config.get(
            'model',
            'cardiffnlp/twitter-roberta-base-sentiment'
        )
        
        # Load model
        self.logger.info(f"Loading sentiment model: {model_name}")
        self.analyzer = pipeline("sentiment-analysis", model=model_name)
        
        self.logger.info("Sentiment scanner initialized")
    
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text for suspicious sentiment patterns.
        
        Args:
            text: Text to scan
            
        Returns:
            Scan result dictionary
        """
        try:
            result = self.analyzer(text[:512])[0]
            
            label = result['label']
            score = result['score']
            
            # Detect extreme negative sentiment (possible manipulation)
            detected = label in ['NEGATIVE', 'negative'] and score >= self.threshold
            
            message = ""
            if detected:
                message = f"Suspicious negative sentiment detected ({score:.2%})"
            
            return self._create_result(
                detected=detected,
                score=score if detected else 0.0,
                message=message,
                sentiment=label,
                confidence=score
            )
            
        except Exception as e:
            self.logger.error(f"Sentiment scan error: {e}")
            return self._create_result(detected=False, error=str(e))
