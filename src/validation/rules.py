"""
VeilArmor v2.0 - Validation Rules

Configurable rules for response validation.
"""

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Pattern, Set

from src.utils.logger import get_logger

logger = get_logger(__name__)


class RuleSeverity(str, Enum):
    """Severity level for rule violations."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RuleCategory(str, Enum):
    """Category of validation rule."""
    LENGTH = "length"
    CONTENT = "content"
    FORMAT = "format"
    SAFETY = "safety"
    QUALITY = "quality"
    CUSTOM = "custom"


@dataclass
class RuleViolation:
    """Represents a validation rule violation."""
    rule_id: str
    rule_name: str
    category: RuleCategory
    severity: RuleSeverity
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    position: Optional[int] = None  # Character position in content


class ValidationRule(ABC):
    """Abstract base class for validation rules."""
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        category: RuleCategory,
        severity: RuleSeverity = RuleSeverity.ERROR,
        enabled: bool = True,
    ):
        """
        Initialize validation rule.
        
        Args:
            rule_id: Unique rule identifier
            name: Human-readable rule name
            category: Rule category
            severity: Violation severity
            enabled: Whether rule is active
        """
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.enabled = enabled
    
    @abstractmethod
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """
        Validate content against this rule.
        
        Args:
            content: Content to validate
            context: Additional context
            
        Returns:
            List of violations (empty if valid)
        """
        pass
    
    def _create_violation(
        self,
        message: str,
        details: Dict[str, Any] = None,
        position: Optional[int] = None,
    ) -> RuleViolation:
        """Create a violation for this rule."""
        return RuleViolation(
            rule_id=self.rule_id,
            rule_name=self.name,
            category=self.category,
            severity=self.severity,
            message=message,
            details=details or {},
            position=position,
        )


# ---------------------------------------------------------------------
# Length Rules
# ---------------------------------------------------------------------

class LengthRule(ValidationRule):
    """Validates content length constraints."""
    
    def __init__(
        self,
        rule_id: str = "length_check",
        min_length: int = 0,
        max_length: int = 100000,
        min_words: int = 0,
        max_words: int = 50000,
        severity: RuleSeverity = RuleSeverity.ERROR,
    ):
        """
        Initialize length rule.
        
        Args:
            rule_id: Unique identifier
            min_length: Minimum character count
            max_length: Maximum character count
            min_words: Minimum word count
            max_words: Maximum word count
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Length Validation",
            category=RuleCategory.LENGTH,
            severity=severity,
        )
        self.min_length = min_length
        self.max_length = max_length
        self.min_words = min_words
        self.max_words = max_words
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Validate content length."""
        violations = []
        
        char_count = len(content)
        word_count = len(content.split())
        
        if char_count < self.min_length:
            violations.append(self._create_violation(
                f"Content too short: {char_count} chars (min: {self.min_length})",
                {"actual": char_count, "min": self.min_length},
            ))
        
        if char_count > self.max_length:
            violations.append(self._create_violation(
                f"Content too long: {char_count} chars (max: {self.max_length})",
                {"actual": char_count, "max": self.max_length},
            ))
        
        if word_count < self.min_words:
            violations.append(self._create_violation(
                f"Too few words: {word_count} (min: {self.min_words})",
                {"actual": word_count, "min": self.min_words},
            ))
        
        if word_count > self.max_words:
            violations.append(self._create_violation(
                f"Too many words: {word_count} (max: {self.max_words})",
                {"actual": word_count, "max": self.max_words},
            ))
        
        return violations


class EmptyResponseRule(ValidationRule):
    """Checks for empty or whitespace-only responses."""
    
    def __init__(self, severity: RuleSeverity = RuleSeverity.ERROR):
        super().__init__(
            rule_id="empty_response",
            name="Empty Response Check",
            category=RuleCategory.LENGTH,
            severity=severity,
        )
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Check for empty response."""
        if not content or not content.strip():
            return [self._create_violation(
                "Response is empty or contains only whitespace",
            )]
        return []


# ---------------------------------------------------------------------
# Content Rules
# ---------------------------------------------------------------------

class ContentRule(ValidationRule):
    """Validates content against blocked patterns."""
    
    def __init__(
        self,
        rule_id: str = "content_check",
        blocked_phrases: List[str] = None,
        blocked_patterns: List[str] = None,
        case_sensitive: bool = False,
        severity: RuleSeverity = RuleSeverity.ERROR,
    ):
        """
        Initialize content rule.
        
        Args:
            rule_id: Unique identifier
            blocked_phrases: Exact phrases to block
            blocked_patterns: Regex patterns to block
            case_sensitive: Case-sensitive matching
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Content Validation",
            category=RuleCategory.CONTENT,
            severity=severity,
        )
        self.blocked_phrases = blocked_phrases or []
        self.case_sensitive = case_sensitive
        
        # Compile patterns
        flags = 0 if case_sensitive else re.IGNORECASE
        self.blocked_patterns: List[Pattern] = []
        
        for pattern in (blocked_patterns or []):
            try:
                self.blocked_patterns.append(re.compile(pattern, flags))
            except re.error as e:
                logger.warning(f"Invalid pattern '{pattern}': {e}")
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Validate content against blocked items."""
        violations = []
        check_content = content if self.case_sensitive else content.lower()
        
        # Check phrases
        for phrase in self.blocked_phrases:
            check_phrase = phrase if self.case_sensitive else phrase.lower()
            if check_phrase in check_content:
                pos = check_content.find(check_phrase)
                violations.append(self._create_violation(
                    f"Blocked phrase detected: '{phrase}'",
                    {"phrase": phrase},
                    position=pos,
                ))
        
        # Check patterns
        for pattern in self.blocked_patterns:
            match = pattern.search(content)
            if match:
                violations.append(self._create_violation(
                    f"Blocked pattern matched: '{pattern.pattern}'",
                    {"pattern": pattern.pattern, "matched": match.group()},
                    position=match.start(),
                ))
        
        return violations


class RequiredContentRule(ValidationRule):
    """Validates that required content is present."""
    
    def __init__(
        self,
        rule_id: str = "required_content",
        required_phrases: List[str] = None,
        required_patterns: List[str] = None,
        require_all: bool = False,
        severity: RuleSeverity = RuleSeverity.WARNING,
    ):
        """
        Initialize required content rule.
        
        Args:
            rule_id: Unique identifier
            required_phrases: Required phrases
            required_patterns: Required regex patterns
            require_all: Require all items (vs any)
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Required Content Check",
            category=RuleCategory.CONTENT,
            severity=severity,
        )
        self.required_phrases = required_phrases or []
        self.required_patterns = [re.compile(p, re.IGNORECASE) for p in (required_patterns or [])]
        self.require_all = require_all
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Validate required content."""
        violations = []
        content_lower = content.lower()
        
        missing_phrases = [
            p for p in self.required_phrases
            if p.lower() not in content_lower
        ]
        
        missing_patterns = [
            p for p in self.required_patterns
            if not p.search(content)
        ]
        
        if self.require_all:
            if missing_phrases:
                violations.append(self._create_violation(
                    f"Missing required phrases: {missing_phrases}",
                    {"missing": missing_phrases},
                ))
            if missing_patterns:
                violations.append(self._create_violation(
                    f"Missing required patterns: {[p.pattern for p in missing_patterns]}",
                    {"missing": [p.pattern for p in missing_patterns]},
                ))
        else:
            # At least one should be present
            if (
                self.required_phrases or self.required_patterns
            ) and (
                len(missing_phrases) == len(self.required_phrases)
                and len(missing_patterns) == len(self.required_patterns)
            ):
                violations.append(self._create_violation(
                    "None of the required content found",
                    {
                        "required_phrases": self.required_phrases,
                        "required_patterns": [p.pattern for p in self.required_patterns],
                    },
                ))
        
        return violations


# ---------------------------------------------------------------------
# Format Rules
# ---------------------------------------------------------------------

class FormatRule(ValidationRule):
    """Validates response format."""
    
    def __init__(
        self,
        rule_id: str = "format_check",
        expected_format: Optional[str] = None,  # json, markdown, plain, etc.
        severity: RuleSeverity = RuleSeverity.WARNING,
    ):
        """
        Initialize format rule.
        
        Args:
            rule_id: Unique identifier
            expected_format: Expected format type
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Format Validation",
            category=RuleCategory.FORMAT,
            severity=severity,
        )
        self.expected_format = expected_format
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Validate content format."""
        violations = []
        
        if self.expected_format == "json":
            violations.extend(self._validate_json(content))
        elif self.expected_format == "markdown":
            violations.extend(self._validate_markdown(content))
        elif self.expected_format == "xml":
            violations.extend(self._validate_xml(content))
        
        return violations
    
    def _validate_json(self, content: str) -> List[RuleViolation]:
        """Validate JSON format."""
        import json
        
        # Try to extract JSON from content
        content = content.strip()
        
        # Handle markdown code blocks
        if content.startswith("```json"):
            content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()
        elif content.startswith("```"):
            content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()
        
        try:
            json.loads(content)
            return []
        except json.JSONDecodeError as e:
            return [self._create_violation(
                f"Invalid JSON format: {e.msg}",
                {"error": str(e), "position": e.pos},
                position=e.pos,
            )]
    
    def _validate_markdown(self, content: str) -> List[RuleViolation]:
        """Validate basic markdown structure."""
        violations = []
        
        # Check for unclosed code blocks
        code_block_count = content.count("```")
        if code_block_count % 2 != 0:
            violations.append(self._create_violation(
                "Unclosed code block detected",
                {"code_block_count": code_block_count},
            ))
        
        return violations
    
    def _validate_xml(self, content: str) -> List[RuleViolation]:
        """Validate XML format."""
        import xml.etree.ElementTree as ET
        
        try:
            ET.fromstring(content)
            return []
        except ET.ParseError as e:
            return [self._create_violation(
                f"Invalid XML format: {str(e)}",
                {"error": str(e)},
            )]


class StructureRule(ValidationRule):
    """Validates response structure (headings, lists, etc.)."""
    
    def __init__(
        self,
        rule_id: str = "structure_check",
        require_headings: bool = False,
        require_lists: bool = False,
        require_code_blocks: bool = False,
        max_paragraph_length: int = 0,  # 0 = no limit
        severity: RuleSeverity = RuleSeverity.INFO,
    ):
        """
        Initialize structure rule.
        
        Args:
            rule_id: Unique identifier
            require_headings: Require markdown headings
            require_lists: Require bullet/numbered lists
            require_code_blocks: Require code blocks
            max_paragraph_length: Max paragraph length
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Structure Validation",
            category=RuleCategory.FORMAT,
            severity=severity,
        )
        self.require_headings = require_headings
        self.require_lists = require_lists
        self.require_code_blocks = require_code_blocks
        self.max_paragraph_length = max_paragraph_length
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Validate content structure."""
        violations = []
        
        if self.require_headings:
            if not re.search(r'^#{1,6}\s+\S', content, re.MULTILINE):
                violations.append(self._create_violation(
                    "No markdown headings found",
                ))
        
        if self.require_lists:
            has_bullet = re.search(r'^[\s]*[-*+]\s+\S', content, re.MULTILINE)
            has_numbered = re.search(r'^[\s]*\d+\.\s+\S', content, re.MULTILINE)
            if not has_bullet and not has_numbered:
                violations.append(self._create_violation(
                    "No lists found in response",
                ))
        
        if self.require_code_blocks:
            if "```" not in content:
                violations.append(self._create_violation(
                    "No code blocks found in response",
                ))
        
        if self.max_paragraph_length > 0:
            paragraphs = content.split('\n\n')
            for i, para in enumerate(paragraphs):
                if len(para) > self.max_paragraph_length:
                    violations.append(self._create_violation(
                        f"Paragraph {i+1} exceeds max length ({len(para)} > {self.max_paragraph_length})",
                        {"paragraph": i+1, "length": len(para)},
                    ))
        
        return violations


# ---------------------------------------------------------------------
# Safety Rules
# ---------------------------------------------------------------------

class SafetyRule(ValidationRule):
    """Validates response safety."""
    
    def __init__(
        self,
        rule_id: str = "safety_check",
        check_pii: bool = True,
        check_credentials: bool = True,
        check_harmful: bool = True,
        severity: RuleSeverity = RuleSeverity.CRITICAL,
    ):
        """
        Initialize safety rule.
        
        Args:
            rule_id: Unique identifier
            check_pii: Check for PII leakage
            check_credentials: Check for credential exposure
            check_harmful: Check for harmful content
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Safety Validation",
            category=RuleCategory.SAFETY,
            severity=severity,
        )
        self.check_pii = check_pii
        self.check_credentials = check_credentials
        self.check_harmful = check_harmful
        
        # PII patterns
        self.pii_patterns = {
            "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "credit_card": re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "phone": re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
        }
        
        # Credential patterns
        self.credential_patterns = {
            "api_key": re.compile(r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?', re.IGNORECASE),
            "password": re.compile(r'(?:password|passwd|pwd)["\s:=]+["\']?([^\s"\']{8,})["\']?', re.IGNORECASE),
            "token": re.compile(r'(?:bearer|token|auth)["\s:=]+["\']?([a-zA-Z0-9._-]{20,})["\']?', re.IGNORECASE),
            "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "private_key": re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'),
        }
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Validate content safety."""
        violations = []
        
        if self.check_pii:
            for pii_type, pattern in self.pii_patterns.items():
                matches = pattern.findall(content)
                if matches:
                    violations.append(self._create_violation(
                        f"PII detected ({pii_type}): {len(matches)} instance(s)",
                        {"type": pii_type, "count": len(matches)},
                    ))
        
        if self.check_credentials:
            for cred_type, pattern in self.credential_patterns.items():
                if pattern.search(content):
                    violations.append(self._create_violation(
                        f"Potential credential exposure ({cred_type})",
                        {"type": cred_type},
                    ))
        
        return violations


class HarmfulContentRule(ValidationRule):
    """Checks for harmful or inappropriate content."""
    
    def __init__(
        self,
        rule_id: str = "harmful_content",
        harmful_categories: List[str] = None,
        severity: RuleSeverity = RuleSeverity.CRITICAL,
    ):
        """
        Initialize harmful content rule.
        
        Args:
            rule_id: Unique identifier
            harmful_categories: Categories to check
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Harmful Content Check",
            category=RuleCategory.SAFETY,
            severity=severity,
        )
        
        self.harmful_patterns = {
            "violence": [
                r'\b(?:kill|murder|attack|weapon|bomb)\b.*\b(?:how|make|build|create)\b',
                r'\b(?:how|make|build|create)\b.*\b(?:kill|murder|attack|weapon|bomb)\b',
            ],
            "illegal": [
                r'\b(?:hack|breach|exploit)\b.*\b(?:how|tutorial|guide|steps)\b',
                r'\b(?:steal|fraud|scam)\b.*\b(?:how|guide|method)\b',
            ],
            "self_harm": [
                r'\b(?:suicide|self[- ]?harm|cut yourself)\b',
            ],
        }
        
        categories = harmful_categories or list(self.harmful_patterns.keys())
        self._compiled_patterns = {}
        
        for cat in categories:
            if cat in self.harmful_patterns:
                self._compiled_patterns[cat] = [
                    re.compile(p, re.IGNORECASE)
                    for p in self.harmful_patterns[cat]
                ]
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Check for harmful content."""
        violations = []
        
        for category, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(content):
                    violations.append(self._create_violation(
                        f"Potentially harmful content detected ({category})",
                        {"category": category},
                    ))
                    break  # One violation per category
        
        return violations


# ---------------------------------------------------------------------
# Quality Rules
# ---------------------------------------------------------------------

class QualityRule(ValidationRule):
    """Validates response quality metrics."""
    
    def __init__(
        self,
        rule_id: str = "quality_check",
        min_unique_words: int = 10,
        max_repetition_ratio: float = 0.3,
        min_sentence_count: int = 1,
        severity: RuleSeverity = RuleSeverity.WARNING,
    ):
        """
        Initialize quality rule.
        
        Args:
            rule_id: Unique identifier
            min_unique_words: Minimum unique words
            max_repetition_ratio: Max word repetition ratio
            min_sentence_count: Minimum sentences
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Quality Validation",
            category=RuleCategory.QUALITY,
            severity=severity,
        )
        self.min_unique_words = min_unique_words
        self.max_repetition_ratio = max_repetition_ratio
        self.min_sentence_count = min_sentence_count
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Validate content quality."""
        violations = []
        
        words = content.lower().split()
        
        if len(words) > 0:
            unique_words = set(words)
            
            if len(unique_words) < self.min_unique_words and len(words) >= self.min_unique_words:
                violations.append(self._create_violation(
                    f"Low vocabulary diversity: {len(unique_words)} unique words",
                    {"unique_words": len(unique_words), "min": self.min_unique_words},
                ))
            
            repetition_ratio = 1 - (len(unique_words) / len(words))
            if repetition_ratio > self.max_repetition_ratio and len(words) > 20:
                violations.append(self._create_violation(
                    f"High repetition ratio: {repetition_ratio:.2%}",
                    {"ratio": repetition_ratio, "max": self.max_repetition_ratio},
                ))
        
        # Count sentences
        sentences = re.split(r'[.!?]+', content)
        sentence_count = len([s for s in sentences if s.strip()])
        
        if sentence_count < self.min_sentence_count:
            violations.append(self._create_violation(
                f"Too few sentences: {sentence_count} (min: {self.min_sentence_count})",
                {"count": sentence_count, "min": self.min_sentence_count},
            ))
        
        return violations


class CoherenceRule(ValidationRule):
    """Checks response coherence."""
    
    def __init__(
        self,
        rule_id: str = "coherence_check",
        check_gibberish: bool = True,
        check_truncation: bool = True,
        severity: RuleSeverity = RuleSeverity.WARNING,
    ):
        """
        Initialize coherence rule.
        
        Args:
            rule_id: Unique identifier
            check_gibberish: Check for gibberish
            check_truncation: Check for truncation
            severity: Violation severity
        """
        super().__init__(
            rule_id=rule_id,
            name="Coherence Check",
            category=RuleCategory.QUALITY,
            severity=severity,
        )
        self.check_gibberish = check_gibberish
        self.check_truncation = check_truncation
    
    def validate(self, content: str, context: Dict[str, Any] = None) -> List[RuleViolation]:
        """Check content coherence."""
        violations = []
        
        if self.check_gibberish:
            # Check for repeated characters
            if re.search(r'(.)\1{10,}', content):
                violations.append(self._create_violation(
                    "Detected repeated character patterns (possible gibberish)",
                ))
            
            # Check for random character sequences
            non_word_ratio = len(re.findall(r'[^a-zA-Z0-9\s.,!?;:\'"()-]', content)) / max(len(content), 1)
            if non_word_ratio > 0.3:
                violations.append(self._create_violation(
                    f"High non-word character ratio: {non_word_ratio:.2%}",
                    {"ratio": non_word_ratio},
                ))
        
        if self.check_truncation:
            content_stripped = content.rstrip()
            
            # Check for mid-sentence truncation
            if content_stripped and content_stripped[-1] not in '.!?"\')]':
                # Check if it looks truncated
                words = content_stripped.split()
                if len(words) > 5:  # Only check longer responses
                    last_word = words[-1].rstrip('.,!?')
                    if len(last_word) > 2 and not last_word[-1].isalnum():
                        violations.append(self._create_violation(
                            "Response may be truncated",
                            {"last_chars": content_stripped[-20:]},
                        ))
        
        return violations
