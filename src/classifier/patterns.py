"""Threat detection patterns"""

import re
from dataclasses import dataclass
from typing import List, Dict, Pattern
from enum import Enum


class ThreatType(str, Enum):
    """Types of threats"""
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    PII_EXPOSURE = "PII_EXPOSURE"
    SENSITIVE_REQUEST = "SENSITIVE_REQUEST"
    HARMFUL_CONTENT = "HARMFUL_CONTENT"
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"


@dataclass
class PatternRule:
    """A pattern matching rule"""
    pattern: Pattern
    threat_type: ThreatType
    severity: str
    weight: float = 1.0


class ThreatPatterns:
    """
    Collection of patterns for threat detection.
    Easy to extend with new patterns.
    """
    
    def __init__(self):
        self.rules: List[PatternRule] = []
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all detection patterns"""
        
        # === PROMPT INJECTION PATTERNS ===
        injection_patterns = [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)",
            r"disregard\s+(all\s+)?(previous|prior|above)",
            r"forget\s+(everything|all|your)\s+(above|previous)",
            r"new\s+instructions?\s*:",
            r"override\s+(all\s+)?(safety|security)",
            r"bypass\s+(all\s+)?(filters?|restrictions?)",
            r"you\s+are\s+now\s+",
            r"from\s+now\s+on\s+you\s+(will|must|should)",
            r"stop\s+being\s+(an?\s+)?ai",
        ]
        
        for pattern in injection_patterns:
            self.rules.append(PatternRule(
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_type=ThreatType.PROMPT_INJECTION,
                severity="HIGH",
                weight=1.0
            ))
        
        # === JAILBREAK PATTERNS ===
        jailbreak_patterns = [
            r"you\s+are\s+(now\s+)?DAN",
            r"do\s+anything\s+now",
            r"pretend\s+(to\s+)?be\s+(evil|unfiltered|unrestricted)",
            r"act\s+as\s+(evil|unrestricted|jailbroken)",
            r"(enable|activate)\s+(developer|dev|debug)\s+mode",
            r"no\s+(ethical|moral)\s+(guidelines?|restrictions?)",
            r"roleplay\s+as\s+.*(evil|villain|unrestricted)",
            r"hypothetically.*no\s+restrictions",
            r"in\s+a\s+fictional\s+(world|scenario)",
        ]
        
        for pattern in jailbreak_patterns:
            self.rules.append(PatternRule(
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_type=ThreatType.JAILBREAK,
                severity="CRITICAL",
                weight=1.0
            ))
        
        # === PII PATTERNS ===
        pii_patterns = [
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "MEDIUM"),  # Email
            (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "MEDIUM"),  # Phone
            (r"\b\d{3}[-]?\d{2}[-]?\d{4}\b", "HIGH"),  # SSN
            (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "HIGH"),  # Credit Card
        ]
        
        for pattern, severity in pii_patterns:
            self.rules.append(PatternRule(
                pattern=re.compile(pattern),
                threat_type=ThreatType.PII_EXPOSURE,
                severity=severity,
                weight=0.8
            ))
        
        # === SENSITIVE REQUEST PATTERNS ===
        sensitive_patterns = [
            r"(admin|root)\s*(password|credentials?|access)",
            r"api\s*key",
            r"secret\s*(key|token)",
            r"database\s*(password|credentials?)",
            r"private\s*key",
            r"(show|tell|give)\s*(me\s+)?(the\s+)?password",
        ]
        
        for pattern in sensitive_patterns:
            self.rules.append(PatternRule(
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_type=ThreatType.SENSITIVE_REQUEST,
                severity="HIGH",
                weight=0.9
            ))
        
        # === SYSTEM PROMPT LEAK PATTERNS ===
        leak_patterns = [
            r"(show|reveal|display|print)\s+(your\s+)?(system\s+)?prompt",
            r"what\s+(are|were)\s+(your\s+)?(initial|original)\s+instructions?",
            r"repeat\s+(the\s+)?(text|content)\s+(above|before)",
            r"summarize\s+everything\s+above",
        ]
        
        for pattern in leak_patterns:
            self.rules.append(PatternRule(
                pattern=re.compile(pattern, re.IGNORECASE),
                threat_type=ThreatType.SYSTEM_PROMPT_LEAK,
                severity="HIGH",
                weight=0.9
            ))
    
    def get_rules(self) -> List[PatternRule]:
        """Get all pattern rules"""
        return self.rules