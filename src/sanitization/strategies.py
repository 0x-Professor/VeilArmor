"""
VeilArmor - Sanitization Strategies

Concrete sanitization strategies for different threat types.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from src.sanitization.base import (
    BaseSanitizationStrategy,
    SanitizationStrategy,
    register_strategy,
)


@register_strategy("pii_redaction")
class PIIRedactionStrategy(BaseSanitizationStrategy):
    """
    Strategy for redacting PII from text.
    """
    
    # PII patterns for redaction
    PII_PATTERNS = {
        "email": (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "[EMAIL_REDACTED]"
        ),
        "phone_us": (
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "[PHONE_REDACTED]"
        ),
        "ssn": (
            r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
            "[SSN_REDACTED]"
        ),
        "credit_card": (
            r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[-.\s]?[0-9]{4}[-.\s]?[0-9]{4}[-.\s]?[0-9]{3,4}\b",
            "[CREDIT_CARD_REDACTED]"
        ),
        "ip_address": (
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "[IP_REDACTED]"
        ),
        "address": (
            r"\b\d{1,5}\s+(?:[A-Za-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b",
            "[ADDRESS_REDACTED]"
        ),
    }
    
    def __init__(self, redaction_marker: str = "[REDACTED]"):
        """Initialize with custom redaction marker."""
        self.redaction_marker = redaction_marker
    
    @property
    def name(self) -> str:
        return "pii_redaction"
    
    @property
    def strategy_type(self) -> SanitizationStrategy:
        return SanitizationStrategy.REDACT
    
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Apply PII redaction."""
        changes = []
        result = text
        
        # Get PII types to redact from context, or use all
        pii_types = None
        if context and "pii_types" in context:
            pii_types = context["pii_types"]
        
        for pii_type, (pattern, replacement) in self.PII_PATTERNS.items():
            if pii_types and pii_type not in pii_types:
                continue
            
            matches = list(re.finditer(pattern, result, re.IGNORECASE))
            for match in reversed(matches):  # Reverse to maintain positions
                original = match.group()
                result = result[:match.start()] + replacement + result[match.end():]
                changes.append({
                    "type": "pii_redaction",
                    "pii_type": pii_type,
                    "original_preview": self._mask_preview(original),
                    "replacement": replacement,
                    "position": match.start(),
                })
        
        return result, changes
    
    def _mask_preview(self, text: str, show_chars: int = 4) -> str:
        """Create masked preview of redacted content."""
        if len(text) <= show_chars:
            return "*" * len(text)
        return "*" * (len(text) - show_chars) + text[-show_chars:]


@register_strategy("toxicity_removal")
class ToxicityRemovalStrategy(BaseSanitizationStrategy):
    """
    Strategy for removing or replacing toxic content.
    """
    
    # Profanity and toxic word patterns
    TOXIC_PATTERNS = [
        (r"\bf+u+c+k+(?:ing|ed|er|s)?\b", "[profanity]"),
        (r"\bs+h+i+t+(?:ty|s)?\b", "[profanity]"),
        (r"\bb+i+t+c+h+(?:es|y)?\b", "[profanity]"),
        (r"\bc+u+n+t+s?\b", "[profanity]"),
        (r"\ba+s+s+(?:hole|wipe)?\b", "[filtered]"),
        (r"\bw+h+o+r+e+s?\b", "[filtered]"),
        (r"\bs+l+u+t+s?\b", "[filtered]"),
        (r"\bd+i+c+k+(?:head)?\b", "[filtered]"),
    ]
    
    # Threat patterns
    THREAT_PATTERNS = [
        (r"\b(?:i\'?ll?|i\'?m\s+going\s+to)\s+(?:kill|murder|hurt|harm)\s+(?:you|your)\b", "[threat removed]"),
        (r"\b(?:you|u)\s+(?:will|are\s+going\s+to)\s+(?:die|suffer|pay)\b", "[threat removed]"),
        (r"\b(?:go\s+)?(?:kill|hang|shoot)\s+(?:yourself|urself)\b", "[threat removed]"),
    ]
    
    def __init__(self, replacement: str = "[removed]"):
        """Initialize with replacement text."""
        self.replacement = replacement
    
    @property
    def name(self) -> str:
        return "toxicity_removal"
    
    @property
    def strategy_type(self) -> SanitizationStrategy:
        return SanitizationStrategy.FILTER
    
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Apply toxicity removal."""
        changes = []
        result = text
        
        # Apply profanity filters
        for pattern, replacement in self.TOXIC_PATTERNS:
            matches = list(re.finditer(pattern, result, re.IGNORECASE))
            for match in reversed(matches):
                result = result[:match.start()] + replacement + result[match.end():]
                changes.append({
                    "type": "toxicity_removal",
                    "category": "profanity",
                    "position": match.start(),
                })
        
        # Apply threat filters
        for pattern, replacement in self.THREAT_PATTERNS:
            matches = list(re.finditer(pattern, result, re.IGNORECASE))
            for match in reversed(matches):
                result = result[:match.start()] + replacement + result[match.end():]
                changes.append({
                    "type": "toxicity_removal",
                    "category": "threat",
                    "position": match.start(),
                })
        
        return result, changes


@register_strategy("injection_neutralization")
class InjectionNeutralizationStrategy(BaseSanitizationStrategy):
    """
    Strategy for neutralizing injection attempts.
    """
    
    # Patterns to neutralize
    INJECTION_PATTERNS = [
        # Prompt injection phrases
        (r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?", "[instruction reference removed]"),
        (r"(?:new|override)\s+instructions?:\s*", ""),
        (r"you\s+are\s+now\s+", ""),
        (r"from\s+now\s+on\s+you\s+(?:are|will)\s+", ""),
        
        # Special tokens
        (r"<\|(?:im_start|im_end|system|user|assistant)\|>", ""),
        (r"\[(?:INST|/INST)\]", ""),
        (r"<<SYS>>|<</SYS>>", ""),
        
        # Role markers
        (r"^(?:system|assistant|user)\s*:\s*", "", re.MULTILINE),
        
        # SQL injection
        (r"(?:\'|\")\s*(?:OR|AND)\s*(?:\'|\"|\d)\s*=", ""),
        (r"(?:UNION\s+(?:ALL\s+)?SELECT)", "[sql removed]"),
        (r"(?:DROP\s+(?:TABLE|DATABASE))", "[sql removed]"),
        
        # Command injection
        (r"(?:;\s*(?:cat|ls|rm|wget|curl|bash|sh))", "[cmd removed]"),
        (r"(?:\|\s*(?:cat|grep|awk|bash|sh))", "[cmd removed]"),
        (r"\$\(.*?\)|\`.*?\`", "[cmd removed]"),
        
        # XSS
        (r"<script[^>]*>.*?</script>", "[script removed]", re.DOTALL | re.IGNORECASE),
        (r"javascript\s*:", ""),
        (r"on(?:load|error|click|mouseover)\s*=", ""),
    ]
    
    @property
    def name(self) -> str:
        return "injection_neutralization"
    
    @property
    def strategy_type(self) -> SanitizationStrategy:
        return SanitizationStrategy.REMOVE
    
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Apply injection neutralization."""
        changes = []
        result = text
        
        for item in self.INJECTION_PATTERNS:
            pattern = item[0]
            replacement = item[1]
            flags = item[2] if len(item) > 2 else 0
            
            matches = list(re.finditer(pattern, result, flags | re.IGNORECASE))
            for match in reversed(matches):
                result = result[:match.start()] + replacement + result[match.end():]
                changes.append({
                    "type": "injection_neutralization",
                    "pattern": pattern[:30],
                    "position": match.start(),
                })
        
        return result, changes


@register_strategy("normalization")
class NormalizationStrategy(BaseSanitizationStrategy):
    """
    Strategy for normalizing text (unicode, whitespace, etc.).
    """
    
    # Zero-width and invisible characters to remove
    INVISIBLE_CHARS = [
        '\u200b', '\u200c', '\u200d', '\u2060',
        '\u2061', '\u2062', '\u2063', '\u2064',
        '\ufeff', '\u00ad', '\u180e',
        '\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
        '\u2066', '\u2067', '\u2068', '\u2069',
    ]
    
    # Homoglyph mappings (lookalike -> standard)
    HOMOGLYPHS = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
        'ɑ': 'a', 'ο': 'o', 'ϲ': 'c', 'ν': 'v', 'ѕ': 's', 'і': 'i',
        'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ɡ': 'g', 'ℎ': 'h',
    }
    
    @property
    def name(self) -> str:
        return "normalization"
    
    @property
    def strategy_type(self) -> SanitizationStrategy:
        return SanitizationStrategy.NORMALIZE
    
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Apply normalization."""
        changes = []
        result = text
        
        # Remove invisible characters
        invisible_removed = 0
        for char in self.INVISIBLE_CHARS:
            count = result.count(char)
            if count > 0:
                result = result.replace(char, '')
                invisible_removed += count
        
        if invisible_removed > 0:
            changes.append({
                "type": "normalization",
                "category": "invisible_chars",
                "count": invisible_removed,
            })
        
        # Replace homoglyphs
        homoglyph_replaced = 0
        for lookalike, standard in self.HOMOGLYPHS.items():
            count = result.count(lookalike)
            if count > 0:
                result = result.replace(lookalike, standard)
                homoglyph_replaced += count
        
        if homoglyph_replaced > 0:
            changes.append({
                "type": "normalization",
                "category": "homoglyphs",
                "count": homoglyph_replaced,
            })
        
        # Normalize whitespace
        original_len = len(result)
        result = re.sub(r'[ \t]+', ' ', result)  # Multiple spaces to single
        result = re.sub(r'\n{3,}', '\n\n', result)  # Multiple newlines
        
        if len(result) != original_len:
            changes.append({
                "type": "normalization",
                "category": "whitespace",
            })
        
        return result, changes


@register_strategy("html_escape")
class HTMLEscapeStrategy(BaseSanitizationStrategy):
    """
    Strategy for HTML escaping special characters.
    """
    
    HTML_ESCAPES = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
    }
    
    @property
    def name(self) -> str:
        return "html_escape"
    
    @property
    def strategy_type(self) -> SanitizationStrategy:
        return SanitizationStrategy.ESCAPE
    
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Apply HTML escaping."""
        changes = []
        result = text
        
        for char, escape in self.HTML_ESCAPES.items():
            count = result.count(char)
            if count > 0:
                result = result.replace(char, escape)
                changes.append({
                    "type": "html_escape",
                    "char": char,
                    "count": count,
                })
        
        return result, changes


@register_strategy("mask")
class MaskingStrategy(BaseSanitizationStrategy):
    """
    Strategy for masking sensitive content with asterisks.
    """
    
    def __init__(self, mask_char: str = "*", show_chars: int = 4):
        """Initialize with mask character and visible char count."""
        self.mask_char = mask_char
        self.show_chars = show_chars
    
    @property
    def name(self) -> str:
        return "masking"
    
    @property
    def strategy_type(self) -> SanitizationStrategy:
        return SanitizationStrategy.MASK
    
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, List[Dict[str, Any]]]:
        """Apply masking based on context."""
        changes = []
        result = text
        
        # Get positions to mask from context
        if not context or "mask_positions" not in context:
            return result, changes
        
        positions = context["mask_positions"]
        
        # Sort positions in reverse order to maintain indices
        for pos in sorted(positions, key=lambda x: x["start"], reverse=True):
            start = pos["start"]
            end = pos["end"]
            original = result[start:end]
            
            masked = self._mask(original)
            result = result[:start] + masked + result[end:]
            
            changes.append({
                "type": "masking",
                "position": start,
                "original_length": len(original),
            })
        
        return result, changes
    
    def _mask(self, text: str) -> str:
        """Mask text showing only last few characters."""
        if len(text) <= self.show_chars:
            return self.mask_char * len(text)
        return self.mask_char * (len(text) - self.show_chars) + text[-self.show_chars:]
