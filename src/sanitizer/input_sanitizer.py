"""Input sanitizer - Cleans user input before sending to LLM"""

import re
from typing import List, Tuple

from .base import BaseSanitizer
from src.core.config import Settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class InputSanitizer(BaseSanitizer):
    """
    Sanitizes user input by:
    - Removing PII (emails, phone numbers, SSNs, credit cards)
    - Removing dangerous patterns
    - Normalizing text
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.placeholder = settings.security.sanitizer.redact_placeholder
        
        # PII patterns to redact
        self.pii_patterns: List[Tuple[re.Pattern, str]] = [
            # Email
            (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), '[EMAIL]'),
            # Phone numbers (various formats)
            (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[PHONE]'),
            # SSN
            (re.compile(r'\b\d{3}[-]?\d{2}[-]?\d{4}\b'), '[SSN]'),
            # Credit Card
            (re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'), '[CREDIT_CARD]'),
            # IP Address
            (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), '[IP_ADDRESS]'),
        ]
        
        # Dangerous patterns to remove
        self.dangerous_patterns: List[re.Pattern] = [
            re.compile(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript\s*:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
        ]
        
        logger.info("InputSanitizer initialized")
    
    def sanitize(self, text: str) -> str:
        """
        Sanitize user input.
        
        Args:
            text: User input text
            
        Returns:
            Sanitized text with PII redacted
        """
        sanitized = text
        
        # Step 1: Remove dangerous patterns
        for pattern in self.dangerous_patterns:
            sanitized = pattern.sub('', sanitized)
        
        # Step 2: Redact PII if enabled
        if self.settings.security.sanitizer.redact_pii:
            for pattern, replacement in self.pii_patterns:
                matches = pattern.findall(sanitized)
                if matches:
                    logger.debug(f"Redacting {len(matches)} PII matches")
                sanitized = pattern.sub(replacement, sanitized)
        
        # Step 3: Normalize whitespace
        sanitized = ' '.join(sanitized.split())
        
        return sanitized