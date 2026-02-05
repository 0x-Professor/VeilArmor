"""
VeilArmor v2.0 - PII Leakage Classifier

Detects PII leakage in LLM outputs that may have been
unintentionally revealed from training data or context.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("pii_leakage")
class PIILeakageClassifier(BaseClassifier):
    """
    Classifier for detecting PII leakage in LLM outputs.
    
    Detects:
    - Training data memorization
    - Context leakage
    - Unintended personal information disclosure
    - Sensitive data exposure
    """
    
    # PII patterns similar to input classifier but tuned for output detection
    PII_PATTERNS: List[Tuple[str, float, str, str]] = [
        # Email addresses
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 0.80, "email", "Email Address"),
        
        # Phone numbers
        (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", 0.75, "phone", "Phone Number"),
        (r"\b(?:\+\d{1,3}[-.\s]?)?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{4}\b", 0.70, "phone_intl", "International Phone"),
        
        # SSN
        (r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", 0.90, "ssn", "Social Security Number"),
        
        # Credit Cards
        (r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{3,4}\b", 0.90, "credit_card", "Credit Card"),
        
        # IP Addresses  
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.60, "ip_address", "IP Address"),
        
        # Physical Addresses
        (r"\b\d{1,5}\s+(?:[A-Za-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b", 0.70, "address", "Physical Address"),
        
        # Account Numbers
        (r"\b(?:account|acct)\s*#?\s*:?\s*\d{8,17}\b", 0.85, "account_number", "Account Number"),
        
        # Medical IDs
        (r"\b(?:MRN|patient\s*ID)\s*:?\s*[A-Z0-9]{6,12}\b", 0.85, "medical_id", "Medical Record"),
    ]
    
    # Leakage indicators - phrases that suggest unintended disclosure
    LEAKAGE_INDICATORS: List[Tuple[str, float]] = [
        # Personal information disclosure
        (r"(?:my|his|her|their)\s+(?:name\s+is|email\s+is|phone\s+(?:number\s+)?is|address\s+is|SSN\s+is)", 0.85),
        (r"(?:can\s+be\s+reached|contact(?:ed)?\s+at|lives?\s+at)", 0.70),
        
        # Specific person references
        (r"(?:john|jane|mr\.|mrs\.|ms\.)\s+[a-z]+\s+(?:works?\s+at|lives?\s+at|can\s+be)", 0.75),
        
        # Internal/confidential markers
        (r"(?:internal|confidential|private|sensitive)\s+(?:information|data|document)", 0.80),
        (r"(?:do\s+not\s+share|not\s+for\s+(?:public|external))", 0.75),
        
        # Training data memorization indicators
        (r"(?:according\s+to\s+(?:my|the)\s+training\s+data)", 0.60),
        (r"(?:i\s+(?:remember|recall)\s+(?:from|that))", 0.50),
    ]
    
    # Context leakage patterns - revealing information from conversation context
    CONTEXT_LEAKAGE_PATTERNS: List[Tuple[str, float]] = [
        (r"(?:you\s+(?:mentioned|said|told\s+me)(?:\s+(?:that\s+)?your)?)\s+(?:name|email|phone|address|SSN)", 0.85),
        (r"(?:based\s+on\s+(?:your|the)\s+(?:previous|earlier)\s+(?:message|information))", 0.60),
        (r"(?:from\s+(?:our|the)\s+(?:conversation|context))", 0.55),
    ]
    
    @property
    def name(self) -> str:
        return "pii_leakage"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.DATA_LEAKAGE
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.OUTPUT
    
    @property
    def description(self) -> str:
        return "Detects PII leakage in LLM outputs"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify LLM output for PII leakage.
        
        Args:
            text: LLM output text to analyze
            context: Optional context with original query and allowed PII
            
        Returns:
            ClassificationResult with leakage assessment
        """
        text_lower = text.lower()
        detected_pii: List[Dict] = []
        leakage_indicators: List[Dict] = []
        max_severity = 0.0
        
        # Extract allowed PII from context (if provided in user query, it's expected)
        allowed_pii = set()
        if context:
            user_query = context.get("user_query", "")
            if user_query:
                # Extract PII from user query - these are "expected" in response
                for pattern, _, pii_type, _ in self.PII_PATTERNS:
                    allowed_pii.update(re.findall(pattern, user_query, re.IGNORECASE))
        
        # Detect PII in output
        for pattern, severity, pii_type, pii_name in self.PII_PATTERNS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    match_str = match if isinstance(match, str) else str(match)
                    
                    # Check if this PII was in the user's query (expected)
                    is_expected = match_str.lower() in {p.lower() for p in allowed_pii}
                    
                    # Lower severity for expected PII
                    adjusted_severity = severity * 0.3 if is_expected else severity
                    
                    detected_pii.append({
                        "type": pii_type,
                        "name": pii_name,
                        "severity": adjusted_severity,
                        "expected": is_expected,
                        "redacted": self._redact(match_str),
                    })
                    max_severity = max(max_severity, adjusted_severity)
            except re.error:
                continue
        
        # Check leakage indicators
        for pattern, severity in self.LEAKAGE_INDICATORS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                leakage_indicators.append({
                    "type": "leakage_indicator",
                    "severity": severity,
                })
                max_severity = max(max_severity, severity)
        
        # Check context leakage
        for pattern, severity in self.CONTEXT_LEAKAGE_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                leakage_indicators.append({
                    "type": "context_leakage",
                    "severity": severity,
                })
                max_severity = max(max_severity, severity)
        
        if not detected_pii and not leakage_indicators:
            return ClassificationResult.no_threat(
                threat_type=self.threat_type,
                classifier_name=self.name,
            )
        
        # Calculate severity
        total_items = len(detected_pii) + len(leakage_indicators)
        unexpected_pii = [p for p in detected_pii if not p.get("expected", False)]
        
        # Boost severity for unexpected PII with leakage indicators
        if unexpected_pii and leakage_indicators:
            max_severity = min(1.0, max_severity + 0.15)
        
        # Boost for multiple unexpected PII items
        if len(unexpected_pii) > 1:
            max_severity = min(1.0, max_severity + 0.05 * min(len(unexpected_pii) - 1, 4))
        
        severity = max_severity
        
        # Confidence
        confidence = min(1.0, 0.65 + (0.05 * min(total_items, 6)))
        
        # Matched patterns
        pii_types = list(set(p["type"] for p in detected_pii))
        matched_patterns = pii_types + [i["type"] for i in leakage_indicators]
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=matched_patterns[:10],
            raw_score=max_severity,
            metadata={
                "pii_count": len(detected_pii),
                "unexpected_pii_count": len(unexpected_pii),
                "expected_pii_count": len(detected_pii) - len(unexpected_pii),
                "leakage_indicator_count": len(leakage_indicators),
                "pii_types": pii_types,
            },
        )
    
    def _redact(self, value: str, show_chars: int = 4) -> str:
        """Redact sensitive value."""
        if len(value) <= show_chars:
            return "*" * len(value)
        return "*" * (len(value) - show_chars) + value[-show_chars:]
