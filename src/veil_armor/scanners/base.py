"""
Base scanner class
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging


class BaseScanner(ABC):
    """
    Abstract base class for all scanners.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        """
        Initialize scanner.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
    
    @abstractmethod
    def scan(self, text: str) -> Dict[str, Any]:
        """
        Scan text for threats.
        
        Args:
            text: Text to scan
            
        Returns:
            Dictionary with scan results
        """
        pass
    
    def _create_result(
        self,
        detected: bool,
        score: float = 0.0,
        message: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create standardized result dictionary.
        
        Args:
            detected: Whether threat was detected
            score: Confidence score (0.0-1.0)
            message: Description message
            **kwargs: Additional fields
            
        Returns:
            Result dictionary
        """
        return {
            'detected': detected,
            'score': score,
            'message': message,
            **kwargs
        }
