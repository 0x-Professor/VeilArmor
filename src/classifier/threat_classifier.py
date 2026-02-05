"""Main threat classifier implementation"""

from typing import List, Dict, Optional, Any
from collections import defaultdict

from .base import BaseClassifier, ClassificationResult
from .patterns import ThreatPatterns, PatternRule, ThreatType
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ThreatClassifier(BaseClassifier):
    """
    Classifies user input for potential threats.
    Uses pattern matching to detect various attack vectors.
    """
    
    # Severity hierarchy for determining final severity
    SEVERITY_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    def __init__(self, settings: Any = None):
        """Initialize classifier with optional settings."""
        self.settings = settings
        self.patterns = ThreatPatterns()
        logger.info(f"ThreatClassifier initialized with {len(self.patterns.get_rules())} rules")
    
    def classify(self, text: str) -> ClassificationResult:
        """
        Classify text for threats.
        
        Args:
            text: Input text to classify
            
        Returns:
            ClassificationResult with detected threats
        """
        detected_threats: List[str] = []
        threat_details: Dict[str, List[str]] = defaultdict(list)
        max_severity = "NONE"
        total_weight = 0.0
        matched_weight = 0.0
        
        # Check each pattern rule
        for rule in self.patterns.get_rules():
            total_weight += rule.weight
            
            match = rule.pattern.search(text)
            if match:
                threat_type = rule.threat_type.value
                
                # Add to detected threats (avoid duplicates)
                if threat_type not in detected_threats:
                    detected_threats.append(threat_type)
                
                # Track matched pattern
                threat_details[threat_type].append(match.group())
                
                # Update severity (keep highest)
                if self._compare_severity(rule.severity, max_severity) > 0:
                    max_severity = rule.severity
                
                matched_weight += rule.weight
                
                logger.debug(f"Matched: {threat_type} - '{match.group()}'")
        
        # Calculate confidence based on matched weights
        confidence = matched_weight / total_weight if total_weight > 0 else 0.0
        
        return ClassificationResult(
            threats=detected_threats,
            severity=max_severity,
            confidence=round(confidence, 3),
            details=dict(threat_details) if threat_details else None
        )
    
    def _compare_severity(self, sev1: str, sev2: str) -> int:
        """Compare two severity levels. Returns >0 if sev1 > sev2"""
        idx1 = self.SEVERITY_ORDER.index(sev1) if sev1 in self.SEVERITY_ORDER else 0
        idx2 = self.SEVERITY_ORDER.index(sev2) if sev2 in self.SEVERITY_ORDER else 0
        return idx1 - idx2