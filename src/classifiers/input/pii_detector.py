"""
VeilArmor v2.0 - PII Detector Classifier

Detects Personally Identifiable Information (PII) exposure
including emails, phone numbers, SSN, credit cards, etc.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.classifiers.base import BaseClassifier, ClassificationResult, ClassifierType, register_classifier
from src import ThreatTypes


@register_classifier("pii_detector")
class PIIDetectorClassifier(BaseClassifier):
    """
    Classifier for detecting PII (Personally Identifiable Information).
    
    Detects various types of PII including:
    - Email addresses
    - Phone numbers (various formats)
    - Social Security Numbers
    - Credit card numbers
    - Physical addresses
    - Names with identifying context
    - Driver's license numbers
    - Passport numbers
    - IP addresses
    - Medical record numbers
    """
    
    # PII patterns with severity and type
    PII_PATTERNS: List[Tuple[str, float, str, str]] = [
        # Email addresses
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 0.85, "email", "Email Address"),
        
        # Phone numbers (various formats)
        (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", 0.80, "phone_us", "US Phone Number"),
        (r"\b(?:\+44[-.\s]?)?\d{4}[-.\s]?\d{6}\b", 0.80, "phone_uk", "UK Phone Number"),
        (r"\b(?:\+49[-.\s]?)?\d{3,4}[-.\s]?\d{7,8}\b", 0.80, "phone_de", "German Phone Number"),
        (r"\b(?:\+\d{1,3}[-.\s]?)?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{4}\b", 0.75, "phone_intl", "International Phone"),
        
        # Social Security Numbers
        (r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", 0.95, "ssn", "Social Security Number"),
        (r"\bSSN\s*:?\s*\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", 0.98, "ssn_labeled", "Labeled SSN"),
        
        # Credit Card Numbers (major providers)
        (r"\b4[0-9]{3}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}\b", 0.95, "cc_visa", "Visa Card"),
        (r"\b5[1-5][0-9]{2}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}\b", 0.95, "cc_mastercard", "Mastercard"),
        (r"\b3[47][0-9]{2}[-.\s]?[0-9]{6}[-.\s]?[0-9]{5}\b", 0.95, "cc_amex", "American Express"),
        (r"\b6(?:011|5[0-9]{2})[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}\b", 0.95, "cc_discover", "Discover Card"),
        (r"\b(?:credit\s*card|card\s*number)\s*:?\s*\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b", 0.98, "cc_labeled", "Labeled Credit Card"),
        
        # CVV/CVC
        (r"\b(?:cvv|cvc|cvv2|cvc2)\s*:?\s*\d{3,4}\b", 0.90, "cvv", "CVV Code"),
        
        # Driver's License (various US state formats)
        (r"\b[A-Z]\d{7}\b", 0.65, "dl_format1", "Driver's License Format 1"),
        (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", 0.60, "dl_format2", "Driver's License Format 2"),
        (r"\b(?:DL|driver\'?s?\s*license)\s*#?\s*:?\s*[A-Z0-9]{6,12}\b", 0.85, "dl_labeled", "Labeled Driver's License"),
        
        # Passport Numbers
        (r"\b(?:passport)\s*#?\s*:?\s*[A-Z0-9]{6,9}\b", 0.85, "passport_labeled", "Labeled Passport"),
        (r"\b[A-Z]{1,2}[0-9]{6,7}\b", 0.50, "passport_format", "Passport Format"),
        
        # IP Addresses
        (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.70, "ipv4", "IPv4 Address"),
        (r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", 0.70, "ipv6", "IPv6 Address"),
        
        # Date of Birth patterns
        (r"\b(?:DOB|date\s*of\s*birth|born\s*on?)\s*:?\s*\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b", 0.80, "dob_labeled", "Date of Birth"),
        (r"\b(?:birthday)\s*:?\s*\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b", 0.75, "birthday", "Birthday"),
        
        # Physical Address patterns
        (r"\b\d{1,5}\s+(?:[A-Za-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Circle|Cir)\b", 0.75, "address_street", "Street Address"),
        (r"\b(?:zip\s*code|postal\s*code)\s*:?\s*\d{5}(?:-\d{4})?\b", 0.70, "zip_code", "ZIP Code"),
        
        # Bank Account Numbers
        (r"\b(?:account|acct)\s*#?\s*:?\s*\d{8,17}\b", 0.90, "bank_account", "Bank Account"),
        (r"\b(?:routing)\s*#?\s*:?\s*\d{9}\b", 0.90, "routing_number", "Routing Number"),
        (r"\b(?:IBAN)\s*:?\s*[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b", 0.90, "iban", "IBAN"),
        
        # Medical Information
        (r"\b(?:MRN|medical\s*record|patient\s*ID)\s*#?\s*:?\s*[A-Z0-9]{6,12}\b", 0.85, "medical_record", "Medical Record Number"),
        (r"\b(?:NPI)\s*:?\s*\d{10}\b", 0.80, "npi", "National Provider Identifier"),
        
        # Tax Identification
        (r"\b(?:EIN|employer\s*ID|tax\s*ID)\s*:?\s*\d{2}[-.]?\d{7}\b", 0.85, "ein", "Employer ID Number"),
        (r"\b(?:TIN|ITIN)\s*:?\s*\d{3}[-.]?\d{2}[-.]?\d{4}\b", 0.85, "tin", "Tax ID Number"),
    ]
    
    # Context patterns that increase PII severity
    PII_CONTEXT_PATTERNS = [
        (r"(?:my|his|her|their)\s+(?:name|email|phone|address|ssn|card)", 0.2),
        (r"(?:personal|private|confidential)\s+(?:information|data|details)", 0.25),
        (r"(?:belongs?\s+to|associated\s+with|owned\s+by)", 0.15),
        (r"(?:send|email|call|contact)\s+(?:me|him|her|them)\s+at", 0.2),
    ]
    
    # Common false positive patterns to reduce severity
    FALSE_POSITIVE_PATTERNS = [
        r"(?:example|test|fake|dummy|sample)\s*:?",
        r"xxx[-.]?xxx[-.]?xxxx",
        r"123[-.]?456[-.]?7890",
        r"john\.?doe@",
        r"555[-.\s]?\d{4}",  # Classic fake phone prefix
    ]
    
    @property
    def name(self) -> str:
        return "pii_detector"
    
    @property
    def threat_type(self) -> str:
        return ThreatTypes.DATA_LEAKAGE
    
    @property
    def classifier_type(self) -> ClassifierType:
        return ClassifierType.INPUT
    
    @property
    def description(self) -> str:
        return "Detects PII including emails, phone numbers, SSN, credit cards, and addresses"
    
    async def classify(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ClassificationResult:
        """
        Classify text for PII presence.
        
        Args:
            text: Input text to analyze
            context: Optional context
            
        Returns:
            ClassificationResult with PII assessment
        """
        matched_pii: List[Dict[str, Any]] = []
        max_severity = 0.0
        total_severity = 0.0
        
        # Check for false positives first
        has_false_positive_context = any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in self.FALSE_POSITIVE_PATTERNS
        )
        
        # Check for PII context
        context_boost = 0.0
        for pattern, boost in self.PII_CONTEXT_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                context_boost = max(context_boost, boost)
        
        # Search for PII patterns
        for pattern, base_severity, pii_type, pii_name in self.PII_PATTERNS:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    # Calculate adjusted severity
                    severity = base_severity + context_boost
                    
                    # Reduce severity for likely false positives
                    if has_false_positive_context:
                        severity *= 0.3
                    
                    severity = min(1.0, severity)
                    
                    for match in matches:
                        # Validate certain patterns
                        if pii_type in ["cc_visa", "cc_mastercard", "cc_amex", "cc_discover"]:
                            if not self._validate_luhn(re.sub(r'[-.\s]', '', match if isinstance(match, str) else match[0])):
                                continue
                        
                        matched_pii.append({
                            "type": pii_type,
                            "name": pii_name,
                            "severity": severity,
                            "redacted": self._redact(match if isinstance(match, str) else str(match)),
                        })
                        max_severity = max(max_severity, severity)
                        total_severity += severity
            except re.error:
                continue
        
        if not matched_pii:
            return ClassificationResult.no_threat(
                threat_type=self.threat_type,
                classifier_name=self.name,
            )
        
        # Calculate overall severity
        severity = min(1.0, max_severity + (0.02 * min(len(matched_pii) - 1, 10)))
        
        # Confidence based on match quality
        confidence = min(1.0, 0.70 + (0.05 * min(len(matched_pii), 6)))
        if has_false_positive_context:
            confidence *= 0.5
        
        # Categorize found PII
        pii_types = list(set(p["type"] for p in matched_pii))
        pii_summary = {t: sum(1 for p in matched_pii if p["type"] == t) for t in pii_types}
        
        return ClassificationResult(
            threat_type=self.threat_type,
            severity=severity,
            confidence=confidence,
            matched_patterns=[p["type"] for p in matched_pii[:10]],
            raw_score=total_severity / len(matched_pii),
            metadata={
                "pii_count": len(matched_pii),
                "pii_types": pii_types,
                "pii_summary": pii_summary,
                "has_false_positive_context": has_false_positive_context,
                "context_boost_applied": context_boost > 0,
            },
        )
    
    def _validate_luhn(self, number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        try:
            digits = [int(d) for d in number if d.isdigit()]
            if len(digits) < 13 or len(digits) > 19:
                return False
            
            checksum = 0
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 1:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            return checksum % 10 == 0
        except (ValueError, TypeError):
            return False
    
    def _redact(self, value: str, show_chars: int = 4) -> str:
        """Redact PII value showing only last few characters."""
        if len(value) <= show_chars:
            return "*" * len(value)
        return "*" * (len(value) - show_chars) + value[-show_chars:]
