"""Output sanitizer - Cleans LLM response before returning to user"""

import re
from typing import List, Tuple

from .base import BaseSanitizer
from src.core.config import Settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class OutputSanitizer(BaseSanitizer):
    """
    Sanitizes LLM output by:
    - Detecting and redacting leaked PII
    - Detecting system prompt leakage
    - Removing potentially harmful content
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        
        # PII patterns (same as input, for response scanning)
        self.pii_patterns: List[Tuple[re.Pattern, str]] = [
            (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '[EMAIL_REDACTED]'),
            (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[PHONE_REDACTED]'),
            (re.compile(r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'), '[SSN_REDACTED]'),
            (re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'), '[CARD_REDACTED]'),
        ]
        
        # System prompt leak indicators
        self.leak_indicators: List[re.Pattern] = [
            re.compile(r'system\s*prompt\s*:', re.IGNORECASE),
            re.compile(r'my\s+instructions\s+(are|were)', re.IGNORECASE),
            re.compile(r'i\s+(was|am)\s+instructed\s+to', re.IGNORECASE),
            re.compile(r'original\s+prompt\s*:', re.IGNORECASE),
        ]
        
        logger.info("OutputSanitizer initialized")
    
    def sanitize(self, text: str) -> str:
        """
        Sanitize LLM response.
        
        Args:
            text: LLM response text
            
        Returns:
            Sanitized response
        """
        sanitized = text
        
        # Step 1: Check for system prompt leakage
        for pattern in self.leak_indicators:
            if pattern.search(sanitized):
                logger.warning("Detected potential system prompt leakage in response")
                # You might want to completely block or heavily redact
                # For now, we'll add a warning
                sanitized = "[Content filtered for security] " + pattern.sub('[FILTERED]', sanitized)
        
        # Step 2: Redact any PII in response
        for pattern, replacement in self.pii_patterns:
            matches = pattern.findall(sanitized)
            if matches:
                logger.debug(f"Redacting {len(matches)} PII in response")
            sanitized = pattern.sub(replacement, sanitized)
        
        return sanitized