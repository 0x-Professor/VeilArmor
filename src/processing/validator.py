"""
VeilArmor - Input Validator

Validates input against configurable rules before processing.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class ValidationSeverity(str, Enum):
    """Severity levels for validation failures."""
    ERROR = "error"  # Blocks processing
    WARNING = "warning"  # Logs but continues
    INFO = "info"  # Informational only


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    text: str
    errors: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    info: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_error(self, rule: str, message: str, details: Optional[Dict] = None) -> None:
        """Add an error."""
        self.errors.append({
            "rule": rule,
            "message": message,
            "severity": ValidationSeverity.ERROR.value,
            "details": details or {},
        })
        self.is_valid = False
    
    def add_warning(self, rule: str, message: str, details: Optional[Dict] = None) -> None:
        """Add a warning."""
        self.warnings.append({
            "rule": rule,
            "message": message,
            "severity": ValidationSeverity.WARNING.value,
            "details": details or {},
        })
    
    def add_info(self, rule: str, message: str, details: Optional[Dict] = None) -> None:
        """Add info message."""
        self.info.append({
            "rule": rule,
            "message": message,
            "severity": ValidationSeverity.INFO.value,
            "details": details or {},
        })
    
    def has_errors(self) -> bool:
        """Check if there are errors."""
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """Check if there are warnings."""
        return len(self.warnings) > 0
    
    def get_all_issues(self) -> List[Dict[str, Any]]:
        """Get all issues."""
        return self.errors + self.warnings + self.info
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "info": self.info,
            "metadata": self.metadata,
        }


@dataclass
class ValidationRule:
    """A validation rule."""
    name: str
    validator: Callable[[str, Dict[str, Any]], bool]
    message: str
    severity: ValidationSeverity = ValidationSeverity.ERROR
    enabled: bool = True
    
    def validate(self, text: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Run validation."""
        return self.validator(text, context or {})


class InputValidator:
    """
    Validates input text against configurable rules.
    
    Performs structural validation before security classification.
    """
    
    # Default configuration
    DEFAULT_MIN_LENGTH = 1
    DEFAULT_MAX_LENGTH = 32000  # 32KB
    DEFAULT_MAX_LINES = 1000
    DEFAULT_ENCODING = "utf-8"
    
    def __init__(
        self,
        min_length: int = DEFAULT_MIN_LENGTH,
        max_length: int = DEFAULT_MAX_LENGTH,
        max_lines: int = DEFAULT_MAX_LINES,
        allowed_languages: Optional[List[str]] = None,
        custom_rules: Optional[List[ValidationRule]] = None,
    ):
        """
        Initialize validator.
        
        Args:
            min_length: Minimum input length
            max_length: Maximum input length
            max_lines: Maximum number of lines
            allowed_languages: Allowed language codes (e.g., ['en', 'es'])
            custom_rules: Custom validation rules
        """
        self.min_length = min_length
        self.max_length = max_length
        self.max_lines = max_lines
        self.allowed_languages = allowed_languages
        self._rules: List[ValidationRule] = []
        
        # Add default rules
        self._add_default_rules()
        
        # Add custom rules
        if custom_rules:
            for rule in custom_rules:
                self.add_rule(rule)
    
    def _add_default_rules(self) -> None:
        """Add default validation rules."""
        # Empty input check
        self.add_rule(ValidationRule(
            name="not_empty",
            validator=lambda text, ctx: len(text.strip()) > 0,
            message="Input cannot be empty",
            severity=ValidationSeverity.ERROR,
        ))
        
        # Minimum length check
        self.add_rule(ValidationRule(
            name="min_length",
            validator=lambda text, ctx: len(text) >= ctx.get("min_length", self.min_length),
            message=f"Input must be at least {self.min_length} characters",
            severity=ValidationSeverity.ERROR,
        ))
        
        # Maximum length check
        self.add_rule(ValidationRule(
            name="max_length",
            validator=lambda text, ctx: len(text) <= ctx.get("max_length", self.max_length),
            message=f"Input exceeds maximum length of {self.max_length} characters",
            severity=ValidationSeverity.ERROR,
        ))
        
        # Line count check
        self.add_rule(ValidationRule(
            name="max_lines",
            validator=lambda text, ctx: text.count("\n") <= ctx.get("max_lines", self.max_lines),
            message=f"Input exceeds maximum of {self.max_lines} lines",
            severity=ValidationSeverity.WARNING,
        ))
        
        # Valid UTF-8 check
        self.add_rule(ValidationRule(
            name="valid_encoding",
            validator=self._check_valid_encoding,
            message="Input contains invalid encoding",
            severity=ValidationSeverity.ERROR,
        ))
        
        # Control character check
        self.add_rule(ValidationRule(
            name="no_control_chars",
            validator=self._check_no_dangerous_control_chars,
            message="Input contains dangerous control characters",
            severity=ValidationSeverity.WARNING,
        ))
        
        # Null byte check
        self.add_rule(ValidationRule(
            name="no_null_bytes",
            validator=lambda text, ctx: "\x00" not in text,
            message="Input contains null bytes",
            severity=ValidationSeverity.ERROR,
        ))
    
    def _check_valid_encoding(self, text: str, context: Dict[str, Any]) -> bool:
        """Check if text has valid encoding."""
        try:
            text.encode(self.DEFAULT_ENCODING)
            return True
        except UnicodeEncodeError:
            return False
    
    def _check_no_dangerous_control_chars(self, text: str, context: Dict[str, Any]) -> bool:
        """Check for dangerous control characters."""
        # Dangerous control characters (excluding common whitespace)
        dangerous_chars = [
            "\x00",  # Null
            "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07",  # SOH-BEL
            "\x0e", "\x0f",  # SO, SI
            "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17",  # DLE-ETB
            "\x18", "\x19", "\x1a", "\x1b", "\x1c", "\x1d", "\x1e", "\x1f",  # CAN-US
            "\x7f",  # DEL
        ]
        
        for char in dangerous_chars:
            if char in text:
                return False
        
        return True
    
    def add_rule(self, rule: ValidationRule) -> None:
        """Add a validation rule."""
        self._rules.append(rule)
    
    def remove_rule(self, name: str) -> bool:
        """Remove a validation rule by name."""
        for i, rule in enumerate(self._rules):
            if rule.name == name:
                del self._rules[i]
                return True
        return False
    
    def enable_rule(self, name: str) -> bool:
        """Enable a rule by name."""
        for rule in self._rules:
            if rule.name == name:
                rule.enabled = True
                return True
        return False
    
    def disable_rule(self, name: str) -> bool:
        """Disable a rule by name."""
        for rule in self._rules:
            if rule.name == name:
                rule.enabled = False
                return True
        return False
    
    def validate(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """
        Validate input text.
        
        Args:
            text: Input text to validate
            context: Optional validation context
            
        Returns:
            ValidationResult
        """
        result = ValidationResult(is_valid=True, text=text)
        ctx = context or {}
        
        # Add configuration to context
        ctx.setdefault("min_length", self.min_length)
        ctx.setdefault("max_length", self.max_length)
        ctx.setdefault("max_lines", self.max_lines)
        
        # Run all enabled rules
        for rule in self._rules:
            if not rule.enabled:
                continue
            
            try:
                is_valid = rule.validate(text, ctx)
                
                if not is_valid:
                    if rule.severity == ValidationSeverity.ERROR:
                        result.add_error(rule.name, rule.message)
                    elif rule.severity == ValidationSeverity.WARNING:
                        result.add_warning(rule.name, rule.message)
                    else:
                        result.add_info(rule.name, rule.message)
            except Exception as e:
                result.add_error(
                    rule.name,
                    f"Validation error: {str(e)}",
                    {"exception": str(e)},
                )
        
        # Add metadata
        result.metadata = {
            "length": len(text),
            "line_count": text.count("\n") + 1,
            "word_count": len(text.split()),
            "rules_checked": len([r for r in self._rules if r.enabled]),
        }
        
        return result
    
    def get_rules(self) -> List[ValidationRule]:
        """Get all validation rules."""
        return self._rules.copy()


class StrictInputValidator(InputValidator):
    """Strict input validator with additional security rules."""
    
    def __init__(self, **kwargs):
        """Initialize strict validator."""
        super().__init__(**kwargs)
        
        # Reduce max length for strict mode
        self.max_length = min(self.max_length, 10000)
        
        # Add stricter rules
        self._add_strict_rules()
    
    def _add_strict_rules(self) -> None:
        """Add stricter validation rules."""
        # No excessive whitespace
        self.add_rule(ValidationRule(
            name="no_excessive_whitespace",
            validator=self._check_no_excessive_whitespace,
            message="Input contains excessive whitespace",
            severity=ValidationSeverity.WARNING,
        ))
        
        # No repeated characters
        self.add_rule(ValidationRule(
            name="no_repeated_chars",
            validator=self._check_no_repeated_chars,
            message="Input contains suspicious repeated characters",
            severity=ValidationSeverity.WARNING,
        ))
        
        # Balanced brackets
        self.add_rule(ValidationRule(
            name="balanced_brackets",
            validator=self._check_balanced_brackets,
            message="Input contains unbalanced brackets",
            severity=ValidationSeverity.WARNING,
        ))
        
        # No homoglyphs
        self.add_rule(ValidationRule(
            name="no_homoglyphs",
            validator=self._check_no_homoglyphs,
            message="Input contains potential homoglyph characters",
            severity=ValidationSeverity.WARNING,
        ))
    
    def _check_no_excessive_whitespace(self, text: str, context: Dict[str, Any]) -> bool:
        """Check for excessive whitespace."""
        # Check for multiple consecutive spaces (more than 10)
        if re.search(r'\s{10,}', text):
            return False
        
        # Check whitespace ratio
        if len(text) > 0:
            whitespace_count = sum(1 for c in text if c.isspace())
            ratio = whitespace_count / len(text)
            if ratio > 0.5:  # More than 50% whitespace
                return False
        
        return True
    
    def _check_no_repeated_chars(self, text: str, context: Dict[str, Any]) -> bool:
        """Check for suspiciously repeated characters."""
        # Check for same character repeated more than 20 times
        if re.search(r'(.)\1{20,}', text):
            return False
        return True
    
    def _check_balanced_brackets(self, text: str, context: Dict[str, Any]) -> bool:
        """Check for balanced brackets."""
        brackets = {'(': ')', '[': ']', '{': '}', '<': '>'}
        stack = []
        
        for char in text:
            if char in brackets:
                stack.append(char)
            elif char in brackets.values():
                if not stack:
                    return False
                if brackets[stack.pop()] != char:
                    return False
        
        # Allow some unbalanced brackets (might be in code/examples)
        return len(stack) <= 10
    
    def _check_no_homoglyphs(self, text: str, context: Dict[str, Any]) -> bool:
        """Check for potential homoglyph characters."""
        # Common homoglyphs
        homoglyphs = {
            'а': 'a',  # Cyrillic
            'е': 'e',
            'о': 'o',
            'р': 'p',
            'с': 'c',
            'х': 'x',
            'Α': 'A',  # Greek
            'Β': 'B',
            'Ε': 'E',
            'Η': 'H',
            'Ι': 'I',
            'Κ': 'K',
            'Μ': 'M',
            'Ν': 'N',
            'Ο': 'O',
            'Ρ': 'P',
            'Τ': 'T',
            'Υ': 'Y',
            'Χ': 'X',
            'Ζ': 'Z',
        }
        
        homoglyph_count = sum(1 for c in text if c in homoglyphs)
        
        # Allow small number of potential homoglyphs (could be legitimate)
        return homoglyph_count <= 5


class APIInputValidator(InputValidator):
    """Input validator optimized for API requests."""
    
    def __init__(self, **kwargs):
        """Initialize API validator."""
        # API-specific defaults
        kwargs.setdefault("max_length", 8000)  # Smaller for API
        kwargs.setdefault("max_lines", 200)
        
        super().__init__(**kwargs)
        
        self._add_api_rules()
    
    def _add_api_rules(self) -> None:
        """Add API-specific validation rules."""
        # Check for API-specific content type markers
        self.add_rule(ValidationRule(
            name="no_raw_html",
            validator=self._check_no_raw_html,
            message="Input appears to contain raw HTML",
            severity=ValidationSeverity.WARNING,
        ))
        
        # Check for base64 encoded content
        self.add_rule(ValidationRule(
            name="no_large_base64",
            validator=self._check_no_large_base64,
            message="Input contains large base64 encoded data",
            severity=ValidationSeverity.WARNING,
        ))
    
    def _check_no_raw_html(self, text: str, context: Dict[str, Any]) -> bool:
        """Check for raw HTML content."""
        # Check for HTML tags
        html_pattern = re.compile(r'<(script|iframe|object|embed|form)[^>]*>', re.IGNORECASE)
        return not html_pattern.search(text)
    
    def _check_no_large_base64(self, text: str, context: Dict[str, Any]) -> bool:
        """Check for large base64 encoded content."""
        # Base64 pattern (at least 100 chars)
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{100,}={0,2}')
        matches = base64_pattern.findall(text)
        
        # Allow small base64 strings, flag large ones
        total_base64_length = sum(len(m) for m in matches)
        return total_base64_length < 1000
