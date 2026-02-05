"""
VeilArmor v2.0 - Classifier Module

Threat detection and classification.
"""

from .base import BaseClassifier, ClassificationResult
from .patterns import ThreatPatterns, ThreatType, PatternRule
from .threat_classifier import ThreatClassifier

__all__ = [
    "BaseClassifier",
    "ClassificationResult",
    "ThreatClassifier",
    "ThreatPatterns",
    "ThreatType",
    "PatternRule",
]
