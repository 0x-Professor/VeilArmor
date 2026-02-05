"""
VeilArmor v2.0 - Input Normalizer

Normalizes input for consistent classification and processing.
"""

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class NormalizationLevel(str, Enum):
    """Normalization intensity levels."""
    NONE = "none"  # No normalization
    LIGHT = "light"  # Basic normalization
    STANDARD = "standard"  # Standard normalization
    AGGRESSIVE = "aggressive"  # Maximum normalization


@dataclass
class NormalizerResult:
    """Result of input normalization."""
    original_text: str
    normalized_text: str
    normalization_level: str
    transformations: List[str] = field(default_factory=list)
    original_hash: str = ""
    normalized_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate hashes."""
        self.original_hash = hashlib.sha256(
            self.original_text.encode()
        ).hexdigest()[:16]
        self.normalized_hash = hashlib.sha256(
            self.normalized_text.encode()
        ).hexdigest()[:16]
    
    @property
    def was_modified(self) -> bool:
        """Check if text was modified."""
        return self.original_hash != self.normalized_hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "original_length": len(self.original_text),
            "normalized_length": len(self.normalized_text),
            "was_modified": self.was_modified,
            "normalization_level": self.normalization_level,
            "transformations": self.transformations,
            "original_hash": self.original_hash,
            "normalized_hash": self.normalized_hash,
            "metadata": self.metadata,
        }


class InputNormalizer:
    """
    Normalizes input text for consistent processing.
    
    Provides multiple normalization levels and strategies
    for different use cases.
    """
    
    def __init__(
        self,
        level: NormalizationLevel = NormalizationLevel.STANDARD,
        lowercase: bool = False,
        remove_accents: bool = False,
        normalize_numbers: bool = False,
        normalize_urls: bool = False,
        normalize_emails: bool = False,
        preserve_structure: bool = True,
    ):
        """
        Initialize normalizer.
        
        Args:
            level: Normalization intensity level
            lowercase: Convert to lowercase
            remove_accents: Remove diacritical marks
            normalize_numbers: Normalize number formats
            normalize_urls: Normalize URLs
            normalize_emails: Normalize email addresses
            preserve_structure: Preserve text structure (paragraphs, lists)
        """
        self.level = level
        self.lowercase = lowercase
        self.remove_accents = remove_accents
        self.normalize_numbers = normalize_numbers
        self.normalize_urls = normalize_urls
        self.normalize_emails = normalize_emails
        self.preserve_structure = preserve_structure
        
        # URL pattern
        self._url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE,
        )
        
        # Email pattern
        self._email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        )
        
        # Number patterns
        self._number_patterns = {
            "phone": re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            "currency": re.compile(r'\$[\d,]+\.?\d*'),
            "percentage": re.compile(r'\d+\.?\d*\s*%'),
        }
    
    def normalize(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> NormalizerResult:
        """
        Normalize input text.
        
        Args:
            text: Input text to normalize
            context: Optional normalization context
            
        Returns:
            NormalizerResult
        """
        transformations = []
        current_text = text
        
        # Apply level-based normalization
        if self.level == NormalizationLevel.NONE:
            return NormalizerResult(
                original_text=text,
                normalized_text=text,
                normalization_level=self.level.value,
            )
        
        # Basic normalization (all levels except NONE)
        if self.level in [
            NormalizationLevel.LIGHT,
            NormalizationLevel.STANDARD,
            NormalizationLevel.AGGRESSIVE,
        ]:
            # Unicode normalization
            new_text = unicodedata.normalize("NFC", current_text)
            if new_text != current_text:
                transformations.append("unicode_nfc")
                current_text = new_text
        
        # Standard normalization
        if self.level in [
            NormalizationLevel.STANDARD,
            NormalizationLevel.AGGRESSIVE,
        ]:
            # Normalize line endings
            new_text = self._normalize_line_endings(current_text)
            if new_text != current_text:
                transformations.append("line_endings")
                current_text = new_text
            
            # Normalize quotes
            new_text = self._normalize_quotes(current_text)
            if new_text != current_text:
                transformations.append("quotes")
                current_text = new_text
            
            # Normalize dashes
            new_text = self._normalize_dashes(current_text)
            if new_text != current_text:
                transformations.append("dashes")
                current_text = new_text
        
        # Aggressive normalization
        if self.level == NormalizationLevel.AGGRESSIVE:
            # Remove accents if configured
            if self.remove_accents:
                new_text = self._remove_accents(current_text)
                if new_text != current_text:
                    transformations.append("remove_accents")
                    current_text = new_text
            
            # Additional aggressive normalizations
            new_text = self._normalize_ellipsis(current_text)
            if new_text != current_text:
                transformations.append("ellipsis")
                current_text = new_text
        
        # Optional normalizations
        if self.lowercase:
            new_text = current_text.lower()
            if new_text != current_text:
                transformations.append("lowercase")
                current_text = new_text
        
        if self.normalize_urls:
            new_text = self._normalize_urls(current_text)
            if new_text != current_text:
                transformations.append("urls")
                current_text = new_text
        
        if self.normalize_emails:
            new_text = self._normalize_emails(current_text)
            if new_text != current_text:
                transformations.append("emails")
                current_text = new_text
        
        if self.normalize_numbers:
            new_text = self._normalize_numbers(current_text)
            if new_text != current_text:
                transformations.append("numbers")
                current_text = new_text
        
        result = NormalizerResult(
            original_text=text,
            normalized_text=current_text,
            normalization_level=self.level.value,
            transformations=transformations,
        )
        
        # Add metadata
        result.metadata = {
            "transformations_count": len(transformations),
            "length_change": len(current_text) - len(text),
        }
        
        return result
    
    def _normalize_line_endings(self, text: str) -> str:
        """Normalize line endings to LF."""
        # Convert CRLF and CR to LF
        text = text.replace("\r\n", "\n")
        text = text.replace("\r", "\n")
        return text
    
    def _normalize_quotes(self, text: str) -> str:
        """Normalize fancy quotes to standard quotes."""
        replacements = {
            """: '"',
            """: '"',
            "'": "'",
            "'": "'",
            "«": '"',
            "»": '"',
            "‹": "'",
            "›": "'",
            "„": '"',
            "‚": "'",
        }
        
        result = text
        for fancy, standard in replacements.items():
            result = result.replace(fancy, standard)
        
        return result
    
    def _normalize_dashes(self, text: str) -> str:
        """Normalize various dashes to standard hyphen."""
        # Map different dash types
        dashes = {
            "–": "-",  # En dash
            "—": "-",  # Em dash
            "―": "-",  # Horizontal bar
            "‒": "-",  # Figure dash
            "−": "-",  # Minus sign
        }
        
        result = text
        for dash, standard in dashes.items():
            result = result.replace(dash, standard)
        
        return result
    
    def _normalize_ellipsis(self, text: str) -> str:
        """Normalize ellipsis."""
        # Convert unicode ellipsis to three dots
        text = text.replace("…", "...")
        # Normalize multiple dots to ellipsis
        text = re.sub(r'\.{4,}', "...", text)
        return text
    
    def _remove_accents(self, text: str) -> str:
        """Remove diacritical marks."""
        # Decompose unicode characters
        nfkd_form = unicodedata.normalize("NFKD", text)
        # Remove combining characters
        return "".join(c for c in nfkd_form if not unicodedata.combining(c))
    
    def _normalize_urls(self, text: str) -> str:
        """Normalize URLs."""
        def normalize_url(match):
            url = match.group(0)
            # Remove trailing punctuation
            while url and url[-1] in ".,;:!?)\"'":
                url = url[:-1]
            # Lowercase the scheme and domain
            parts = url.split("://", 1)
            if len(parts) == 2:
                scheme, rest = parts
                domain_end = rest.find("/")
                if domain_end == -1:
                    domain = rest
                    path = ""
                else:
                    domain = rest[:domain_end]
                    path = rest[domain_end:]
                return f"{scheme.lower()}://{domain.lower()}{path}"
            return url
        
        return self._url_pattern.sub(normalize_url, text)
    
    def _normalize_emails(self, text: str) -> str:
        """Normalize email addresses."""
        def normalize_email(match):
            email = match.group(0)
            return email.lower()
        
        return self._email_pattern.sub(normalize_email, text)
    
    def _normalize_numbers(self, text: str) -> str:
        """Normalize number formats."""
        result = text
        
        # Normalize phone numbers (US format)
        def normalize_phone(match):
            digits = re.sub(r'\D', '', match.group(0))
            return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
        
        result = self._number_patterns["phone"].sub(normalize_phone, result)
        
        return result
    
    def set_level(self, level: NormalizationLevel) -> None:
        """Set normalization level."""
        self.level = level


class SemanticNormalizer(InputNormalizer):
    """
    Normalizer focused on semantic preservation.
    
    Normalizes for meaning comparison while preserving semantic content.
    """
    
    def __init__(self, **kwargs):
        """Initialize semantic normalizer."""
        kwargs.setdefault("level", NormalizationLevel.STANDARD)
        kwargs.setdefault("lowercase", True)
        kwargs.setdefault("remove_accents", True)
        kwargs.setdefault("normalize_numbers", False)  # Preserve numeric meaning
        kwargs.setdefault("normalize_urls", True)
        kwargs.setdefault("normalize_emails", True)
        
        super().__init__(**kwargs)
        
        # Stopwords for semantic normalization
        self._stopwords: Set[str] = {
            "a", "an", "the", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will",
            "would", "could", "should", "may", "might", "must", "shall",
            "can", "need", "dare", "ought", "used", "to", "of", "in",
            "for", "on", "with", "at", "by", "from", "as", "into",
            "through", "during", "before", "after", "above", "below",
            "between", "under", "again", "further", "then", "once",
        }
    
    def normalize_for_comparison(self, text: str) -> str:
        """
        Normalize text for semantic comparison.
        
        Args:
            text: Input text
            
        Returns:
            Normalized text for comparison
        """
        result = self.normalize(text)
        normalized = result.normalized_text
        
        # Remove punctuation
        normalized = re.sub(r'[^\w\s]', ' ', normalized)
        
        # Collapse whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        return normalized
    
    def normalize_without_stopwords(self, text: str) -> str:
        """
        Normalize and remove stopwords.
        
        Args:
            text: Input text
            
        Returns:
            Normalized text without stopwords
        """
        normalized = self.normalize_for_comparison(text)
        
        # Remove stopwords
        words = normalized.split()
        filtered = [w for w in words if w.lower() not in self._stopwords]
        
        return " ".join(filtered)


class CacheKeyNormalizer(InputNormalizer):
    """
    Normalizer for generating consistent cache keys.
    
    Produces deterministic normalized text for cache key generation.
    """
    
    def __init__(self, **kwargs):
        """Initialize cache key normalizer."""
        kwargs.setdefault("level", NormalizationLevel.AGGRESSIVE)
        kwargs.setdefault("lowercase", True)
        kwargs.setdefault("remove_accents", True)
        kwargs.setdefault("normalize_urls", True)
        kwargs.setdefault("normalize_emails", True)
        kwargs.setdefault("normalize_numbers", True)
        
        super().__init__(**kwargs)
    
    def generate_cache_key(self, text: str, prefix: str = "") -> str:
        """
        Generate a cache key from text.
        
        Args:
            text: Input text
            prefix: Optional key prefix
            
        Returns:
            Cache key string
        """
        result = self.normalize(text)
        
        # Create deterministic hash
        content_hash = hashlib.sha256(
            result.normalized_text.encode()
        ).hexdigest()[:32]
        
        if prefix:
            return f"{prefix}:{content_hash}"
        
        return content_hash
    
    def generate_similarity_key(
        self,
        text: str,
        prefix: str = "",
    ) -> str:
        """
        Generate a key for similarity-based caching.
        
        Uses a simpler normalization for fuzzy matching.
        
        Args:
            text: Input text
            prefix: Optional key prefix
            
        Returns:
            Similarity key string
        """
        # Simple normalization for similarity
        normalized = text.lower().strip()
        normalized = re.sub(r'\s+', ' ', normalized)
        normalized = re.sub(r'[^\w\s]', '', normalized)
        
        # Take first N words for similarity key
        words = normalized.split()[:20]
        key_text = " ".join(words)
        
        content_hash = hashlib.sha256(key_text.encode()).hexdigest()[:16]
        
        if prefix:
            return f"{prefix}:sim:{content_hash}"
        
        return f"sim:{content_hash}"
