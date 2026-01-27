"""Base classifier interface"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ClassificationResult:
    """Result from threat classification"""
    threats: List[str]
    severity: str
    confidence: float
    details: Optional[dict] = None


class BaseClassifier(ABC):
    """Abstract base class for classifiers"""
    
    @abstractmethod
    def classify(self, text: str) -> ClassificationResult:
        """
        Classify text for threats.
        
        Args:
            text: Input text to classify
            
        Returns:
            ClassificationResult with detected threats
        """
        pass