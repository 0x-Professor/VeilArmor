"""Base sanitizer interface"""

from abc import ABC, abstractmethod


class BaseSanitizer(ABC):
    """Abstract base class for sanitizers"""
    
    @abstractmethod
    def sanitize(self, text: str) -> str:
        """
        Sanitize input text.
        
        Args:
            text: Input text to sanitize
            
        Returns:
            Sanitized text
        """
        pass