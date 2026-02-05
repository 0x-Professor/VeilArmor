"""
VeilArmor v2.0 - Base Classifier

Defines the abstract base class for all classifiers and the ClassificationResult model.
All classifiers must extend BaseClassifier and implement the classify method.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Type

from src.logging import get_logger
from src import Layers, ThreatTypes

logger = get_logger(__name__, layer=Layers.CLASSIFICATION_ENGINE)


class ClassifierType(str, Enum):
    """Type of classifier."""
    INPUT = "input"
    OUTPUT = "output"


@dataclass
class ClassificationResult:
    """
    Result of a classification operation.
    
    Attributes:
        threat_type: Type of threat detected (from ThreatTypes)
        severity: Severity score (0.0 - 1.0, higher is more severe)
        confidence: Confidence in the classification (0.0 - 1.0)
        matched_patterns: List of patterns that matched
        metadata: Additional classification metadata
        raw_score: Raw classifier score before normalization
        classifier_name: Name of the classifier that produced this result
        processing_time_ms: Time taken to classify in milliseconds
        is_threat: Whether this result indicates a threat
    """
    
    threat_type: str
    severity: float = 0.0
    confidence: float = 0.0
    matched_patterns: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_score: float = 0.0
    classifier_name: str = ""
    processing_time_ms: float = 0.0
    
    def __post_init__(self) -> None:
        """Validate and normalize values."""
        self.severity = max(0.0, min(1.0, self.severity))
        self.confidence = max(0.0, min(1.0, self.confidence))
        self.raw_score = max(0.0, min(1.0, self.raw_score))
    
    @property
    def is_threat(self) -> bool:
        """Check if this result indicates a potential threat."""
        return self.severity > 0.0 and self.confidence > 0.0
    
    @property
    def weighted_score(self) -> float:
        """Calculate weighted score (severity * confidence)."""
        return self.severity * self.confidence
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "matched_patterns": self.matched_patterns,
            "metadata": self.metadata,
            "raw_score": self.raw_score,
            "classifier_name": self.classifier_name,
            "processing_time_ms": self.processing_time_ms,
            "is_threat": self.is_threat,
            "weighted_score": self.weighted_score,
        }
    
    @classmethod
    def no_threat(
        cls,
        threat_type: str,
        classifier_name: str = "",
        processing_time_ms: float = 0.0
    ) -> "ClassificationResult":
        """Create a result indicating no threat detected."""
        return cls(
            threat_type=threat_type,
            severity=0.0,
            confidence=1.0,  # High confidence that there's no threat
            classifier_name=classifier_name,
            processing_time_ms=processing_time_ms,
        )
    
    @classmethod
    def error_result(
        cls,
        threat_type: str,
        classifier_name: str = "",
        error_message: str = "",
        processing_time_ms: float = 0.0
    ) -> "ClassificationResult":
        """Create a result indicating classification error."""
        return cls(
            threat_type=threat_type,
            severity=0.0,
            confidence=0.0,
            classifier_name=classifier_name,
            processing_time_ms=processing_time_ms,
            metadata={"error": error_message, "status": "error"},
        )


class BaseClassifier(ABC):
    """
    Abstract base class for all classifiers.
    
    All classifiers must extend this class and implement:
    - classify(): The main classification logic
    - name: Property returning the classifier name
    - threat_type: Property returning the threat type this classifier detects
    - classifier_type: Property returning whether this is an input or output classifier
    
    Attributes:
        enabled: Whether the classifier is enabled
        weight: Weight for score aggregation
        threshold: Minimum score to consider a threat
        timeout_seconds: Maximum execution time
        options: Additional classifier-specific options
    """
    
    def __init__(
        self,
        enabled: bool = True,
        weight: float = 1.0,
        threshold: float = 0.5,
        timeout_seconds: float = 5.0,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the classifier.
        
        Args:
            enabled: Whether the classifier is enabled
            weight: Weight for score aggregation (0.0 - 10.0)
            threshold: Minimum score threshold (0.0 - 1.0)
            timeout_seconds: Maximum execution time in seconds
            options: Additional classifier-specific options
        """
        self.enabled = enabled
        self.weight = max(0.0, min(10.0, weight))
        self.threshold = max(0.0, min(1.0, threshold))
        self.timeout_seconds = max(0.1, timeout_seconds)
        self.options = options or {}
        
        # Health tracking
        self._total_calls = 0
        self._total_errors = 0
        self._total_time_ms = 0.0
        
        logger.debug(
            "Classifier initialized",
            component=self.name,
            enabled=self.enabled,
            weight=self.weight,
            threshold=self.threshold,
        )
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the classifier name."""
        pass
    
    @property
    @abstractmethod
    def threat_type(self) -> str:
        """Return the threat type this classifier detects."""
        pass
    
    @property
    @abstractmethod
    def classifier_type(self) -> ClassifierType:
        """Return whether this is an input or output classifier."""
        pass
    
    @property
    def description(self) -> str:
        """Return a description of what this classifier does."""
        return f"Detects {self.threat_type} threats"
    
    @abstractmethod
    async def classify(self, text: str, context: Optional[Dict[str, Any]] = None) -> ClassificationResult:
        """
        Classify the given text for threats.
        
        This is the main method that must be implemented by all classifiers.
        
        Args:
            text: The text to classify
            context: Optional context including conversation history, user info, etc.
            
        Returns:
            ClassificationResult with threat assessment
        """
        pass
    
    async def run(self, text: str, context: Optional[Dict[str, Any]] = None) -> ClassificationResult:
        """
        Run the classifier with timing and error handling.
        
        This wrapper method handles:
        - Timing measurement
        - Error handling
        - Health metrics tracking
        - Logging
        
        Args:
            text: The text to classify
            context: Optional context
            
        Returns:
            ClassificationResult
        """
        if not self.enabled:
            logger.debug(
                "Classifier disabled, skipping",
                component=self.name,
            )
            return ClassificationResult.no_threat(
                threat_type=self.threat_type,
                classifier_name=self.name,
            )
        
        start_time = time.perf_counter()
        self._total_calls += 1
        
        try:
            logger.debug(
                "Running classifier",
                component=self.name,
                text_length=len(text),
            )
            
            result = await self.classify(text, context)
            
            # Set classifier name if not set
            if not result.classifier_name:
                result.classifier_name = self.name
            
            # Calculate processing time
            processing_time_ms = (time.perf_counter() - start_time) * 1000
            result.processing_time_ms = processing_time_ms
            self._total_time_ms += processing_time_ms
            
            # Log result
            if result.is_threat:
                logger.info(
                    "Threat detected",
                    component=self.name,
                    threat_type=result.threat_type,
                    severity=result.severity,
                    confidence=result.confidence,
                    matched_patterns=result.matched_patterns[:3],  # Limit logged patterns
                    processing_time_ms=processing_time_ms,
                )
            else:
                logger.debug(
                    "No threat detected",
                    component=self.name,
                    processing_time_ms=processing_time_ms,
                )
            
            return result
            
        except Exception as e:
            processing_time_ms = (time.perf_counter() - start_time) * 1000
            self._total_errors += 1
            
            logger.error(
                "Classifier error",
                component=self.name,
                error=str(e),
                processing_time_ms=processing_time_ms,
                exc_info=True,
            )
            
            return ClassificationResult.error_result(
                threat_type=self.threat_type,
                classifier_name=self.name,
                error_message=str(e),
                processing_time_ms=processing_time_ms,
            )
    
    def get_health(self) -> Dict[str, Any]:
        """
        Get classifier health metrics.
        
        Returns:
            Dictionary with health metrics
        """
        avg_time = self._total_time_ms / self._total_calls if self._total_calls > 0 else 0.0
        error_rate = self._total_errors / self._total_calls if self._total_calls > 0 else 0.0
        
        return {
            "name": self.name,
            "enabled": self.enabled,
            "total_calls": self._total_calls,
            "total_errors": self._total_errors,
            "error_rate": error_rate,
            "avg_processing_time_ms": avg_time,
            "total_processing_time_ms": self._total_time_ms,
        }
    
    def reset_metrics(self) -> None:
        """Reset health metrics."""
        self._total_calls = 0
        self._total_errors = 0
        self._total_time_ms = 0.0
    
    def __repr__(self) -> str:
        """Return string representation."""
        return (
            f"{self.__class__.__name__}("
            f"name={self.name!r}, "
            f"enabled={self.enabled}, "
            f"weight={self.weight}, "
            f"threshold={self.threshold})"
        )


# Registry for classifier classes
_classifier_registry: Dict[str, Type[BaseClassifier]] = {}


def register_classifier(name: str):
    """
    Decorator to register a classifier class.
    
    Args:
        name: Unique name for the classifier
        
    Returns:
        Decorator function
        
    Example:
        @register_classifier("my_classifier")
        class MyClassifier(BaseClassifier):
            ...
    """
    def decorator(cls: Type[BaseClassifier]) -> Type[BaseClassifier]:
        _classifier_registry[name] = cls
        return cls
    return decorator


def get_classifier_class(name: str) -> Optional[Type[BaseClassifier]]:
    """
    Get a registered classifier class by name.
    
    Args:
        name: Classifier name
        
    Returns:
        Classifier class or None if not found
    """
    return _classifier_registry.get(name)


def list_registered_classifiers() -> List[str]:
    """
    List all registered classifier names.
    
    Returns:
        List of classifier names
    """
    return list(_classifier_registry.keys())
