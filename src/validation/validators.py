"""
VeilArmor - Response Validators

Composable validators for different validation aspects.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from src.validation.rules import (
    ValidationRule,
    RuleViolation,
    RuleSeverity,
    RuleCategory,
    LengthRule,
    EmptyResponseRule,
    ContentRule,
    FormatRule,
    StructureRule,
    SafetyRule,
    HarmfulContentRule,
    QualityRule,
    CoherenceRule,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ValidationStatus(str, Enum):
    """Validation result status."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"


@dataclass
class ValidatorResult:
    """Result from a single validator."""
    validator_name: str
    status: ValidationStatus
    violations: List[RuleViolation] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    
    @property
    def is_valid(self) -> bool:
        """Check if validation passed without errors."""
        return self.status == ValidationStatus.PASSED
    
    @property
    def error_count(self) -> int:
        """Count error-level violations."""
        return len([
            v for v in self.violations
            if v.severity in (RuleSeverity.ERROR, RuleSeverity.CRITICAL)
        ])
    
    @property
    def warning_count(self) -> int:
        """Count warning-level violations."""
        return len([
            v for v in self.violations
            if v.severity == RuleSeverity.WARNING
        ])


class BaseValidator(ABC):
    """Abstract base class for validators."""
    
    def __init__(
        self,
        name: str,
        enabled: bool = True,
        rules: List[ValidationRule] = None,
    ):
        """
        Initialize validator.
        
        Args:
            name: Validator name
            enabled: Whether validator is active
            rules: Validation rules
        """
        self.name = name
        self.enabled = enabled
        self.rules: List[ValidationRule] = rules or []
    
    def add_rule(self, rule: ValidationRule) -> None:
        """Add a validation rule."""
        self.rules.append(rule)
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                del self.rules[i]
                return True
        return False
    
    @abstractmethod
    async def validate(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidatorResult:
        """
        Validate content.
        
        Args:
            content: Content to validate
            context: Additional context
            
        Returns:
            Validation result
        """
        pass
    
    def _determine_status(
        self,
        violations: List[RuleViolation],
    ) -> ValidationStatus:
        """Determine overall status from violations."""
        if not violations:
            return ValidationStatus.PASSED
        
        has_error = any(
            v.severity in (RuleSeverity.ERROR, RuleSeverity.CRITICAL)
            for v in violations
        )
        
        if has_error:
            return ValidationStatus.FAILED
        
        return ValidationStatus.WARNING


class ResponseValidator(BaseValidator):
    """
    General response validator.
    
    Applies all configured rules to validate responses.
    """
    
    def __init__(
        self,
        name: str = "ResponseValidator",
        enabled: bool = True,
        rules: List[ValidationRule] = None,
        fail_fast: bool = False,
    ):
        """
        Initialize response validator.
        
        Args:
            name: Validator name
            enabled: Whether enabled
            rules: Validation rules
            fail_fast: Stop on first error
        """
        super().__init__(name, enabled, rules)
        self.fail_fast = fail_fast
    
    async def validate(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidatorResult:
        """Validate response content."""
        import time
        start_time = time.time()
        
        violations = []
        context = context or {}
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            rule_violations = rule.validate(content, context)
            violations.extend(rule_violations)
            
            if self.fail_fast and any(
                v.severity in (RuleSeverity.ERROR, RuleSeverity.CRITICAL)
                for v in rule_violations
            ):
                break
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ValidatorResult(
            validator_name=self.name,
            status=self._determine_status(violations),
            violations=violations,
            duration_ms=duration_ms,
        )


class ContentValidator(BaseValidator):
    """
    Content-focused validator.
    
    Validates content against blocked/required items.
    """
    
    def __init__(
        self,
        blocked_phrases: List[str] = None,
        blocked_patterns: List[str] = None,
        required_phrases: List[str] = None,
        case_sensitive: bool = False,
    ):
        """
        Initialize content validator.
        
        Args:
            blocked_phrases: Phrases to block
            blocked_patterns: Patterns to block
            required_phrases: Required phrases
            case_sensitive: Case-sensitive matching
        """
        super().__init__("ContentValidator")
        
        if blocked_phrases or blocked_patterns:
            self.add_rule(ContentRule(
                rule_id="blocked_content",
                blocked_phrases=blocked_phrases,
                blocked_patterns=blocked_patterns,
                case_sensitive=case_sensitive,
            ))
        
        if required_phrases:
            from src.validation.rules import RequiredContentRule
            self.add_rule(RequiredContentRule(
                rule_id="required_content",
                required_phrases=required_phrases,
            ))
    
    async def validate(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidatorResult:
        """Validate content."""
        import time
        start_time = time.time()
        
        violations = []
        context = context or {}
        
        for rule in self.rules:
            if rule.enabled:
                violations.extend(rule.validate(content, context))
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ValidatorResult(
            validator_name=self.name,
            status=self._determine_status(violations),
            violations=violations,
            duration_ms=duration_ms,
        )


class FormatValidator(BaseValidator):
    """
    Format-focused validator.
    
    Validates response format (JSON, markdown, etc.).
    """
    
    def __init__(
        self,
        expected_format: Optional[str] = None,
        check_structure: bool = True,
        require_headings: bool = False,
        require_code_blocks: bool = False,
    ):
        """
        Initialize format validator.
        
        Args:
            expected_format: Expected format type
            check_structure: Check structure
            require_headings: Require headings
            require_code_blocks: Require code blocks
        """
        super().__init__("FormatValidator")
        
        if expected_format:
            self.add_rule(FormatRule(
                rule_id="format_check",
                expected_format=expected_format,
            ))
        
        if check_structure:
            self.add_rule(StructureRule(
                rule_id="structure_check",
                require_headings=require_headings,
                require_code_blocks=require_code_blocks,
            ))
    
    async def validate(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidatorResult:
        """Validate format."""
        import time
        start_time = time.time()
        
        violations = []
        context = context or {}
        
        for rule in self.rules:
            if rule.enabled:
                violations.extend(rule.validate(content, context))
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ValidatorResult(
            validator_name=self.name,
            status=self._determine_status(violations),
            violations=violations,
            duration_ms=duration_ms,
        )


class SafetyValidator(BaseValidator):
    """
    Safety-focused validator.
    
    Validates for PII, credentials, and harmful content.
    """
    
    def __init__(
        self,
        check_pii: bool = True,
        check_credentials: bool = True,
        check_harmful: bool = True,
        harmful_categories: List[str] = None,
    ):
        """
        Initialize safety validator.
        
        Args:
            check_pii: Check for PII
            check_credentials: Check for credentials
            check_harmful: Check for harmful content
            harmful_categories: Harmful categories to check
        """
        super().__init__("SafetyValidator")
        
        if check_pii or check_credentials:
            self.add_rule(SafetyRule(
                rule_id="safety_check",
                check_pii=check_pii,
                check_credentials=check_credentials,
            ))
        
        if check_harmful:
            self.add_rule(HarmfulContentRule(
                rule_id="harmful_check",
                harmful_categories=harmful_categories,
            ))
    
    async def validate(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidatorResult:
        """Validate safety."""
        import time
        start_time = time.time()
        
        violations = []
        context = context or {}
        
        for rule in self.rules:
            if rule.enabled:
                violations.extend(rule.validate(content, context))
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ValidatorResult(
            validator_name=self.name,
            status=self._determine_status(violations),
            violations=violations,
            duration_ms=duration_ms,
        )


class QualityValidator(BaseValidator):
    """
    Quality-focused validator.
    
    Validates response quality metrics.
    """
    
    def __init__(
        self,
        min_length: int = 1,
        max_length: int = 100000,
        check_empty: bool = True,
        check_coherence: bool = True,
        min_unique_words: int = 5,
    ):
        """
        Initialize quality validator.
        
        Args:
            min_length: Minimum length
            max_length: Maximum length
            check_empty: Check for empty
            check_coherence: Check coherence
            min_unique_words: Min unique words
        """
        super().__init__("QualityValidator")
        
        if check_empty:
            self.add_rule(EmptyResponseRule())
        
        self.add_rule(LengthRule(
            min_length=min_length,
            max_length=max_length,
        ))
        
        self.add_rule(QualityRule(
            min_unique_words=min_unique_words,
        ))
        
        if check_coherence:
            self.add_rule(CoherenceRule())
    
    async def validate(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidatorResult:
        """Validate quality."""
        import time
        start_time = time.time()
        
        violations = []
        context = context or {}
        
        for rule in self.rules:
            if rule.enabled:
                violations.extend(rule.validate(content, context))
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ValidatorResult(
            validator_name=self.name,
            status=self._determine_status(violations),
            violations=violations,
            duration_ms=duration_ms,
        )


class CompositeValidator(BaseValidator):
    """
    Composite validator combining multiple validators.
    
    Runs validators in parallel for efficiency.
    """
    
    def __init__(
        self,
        validators: List[BaseValidator] = None,
        parallel: bool = True,
        stop_on_critical: bool = True,
    ):
        """
        Initialize composite validator.
        
        Args:
            validators: Child validators
            parallel: Run in parallel
            stop_on_critical: Stop on critical violation
        """
        super().__init__("CompositeValidator")
        self.validators = validators or []
        self.parallel = parallel
        self.stop_on_critical = stop_on_critical
    
    def add_validator(self, validator: BaseValidator) -> None:
        """Add a child validator."""
        self.validators.append(validator)
    
    async def validate(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidatorResult:
        """Run all validators."""
        import time
        start_time = time.time()
        
        context = context or {}
        all_violations = []
        
        if self.parallel:
            # Run validators in parallel
            tasks = [
                v.validate(content, context)
                for v in self.validators
                if v.enabled
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    logger.error("Validator error", error=str(result))
                    continue
                
                all_violations.extend(result.violations)
                
                if self.stop_on_critical:
                    if any(v.severity == RuleSeverity.CRITICAL for v in result.violations):
                        break
        else:
            # Run validators sequentially
            for validator in self.validators:
                if not validator.enabled:
                    continue
                
                result = await validator.validate(content, context)
                all_violations.extend(result.violations)
                
                if self.stop_on_critical:
                    if any(v.severity == RuleSeverity.CRITICAL for v in result.violations):
                        break
        
        duration_ms = (time.time() - start_time) * 1000
        
        return ValidatorResult(
            validator_name=self.name,
            status=self._determine_status(all_violations),
            violations=all_violations,
            duration_ms=duration_ms,
        )


# ---------------------------------------------------------------------
# Pre-configured Validators
# ---------------------------------------------------------------------

def create_default_validator() -> CompositeValidator:
    """Create default validator with standard rules."""
    return CompositeValidator(
        validators=[
            QualityValidator(),
            SafetyValidator(),
        ],
    )


def create_strict_validator() -> CompositeValidator:
    """Create strict validator for sensitive content."""
    return CompositeValidator(
        validators=[
            QualityValidator(
                min_length=10,
                min_unique_words=10,
            ),
            SafetyValidator(
                check_pii=True,
                check_credentials=True,
                check_harmful=True,
            ),
            ContentValidator(
                blocked_patterns=[
                    r'\b(?:password|secret|key)[:\s]*["\']?[a-zA-Z0-9_-]{8,}["\']?',
                ],
            ),
        ],
        stop_on_critical=True,
    )


def create_api_validator(
    max_length: int = 50000,
    expected_format: str = None,
) -> CompositeValidator:
    """Create validator for API responses."""
    validators = [
        QualityValidator(
            max_length=max_length,
            check_coherence=False,  # API may have structured data
        ),
        SafetyValidator(
            check_credentials=True,
        ),
    ]
    
    if expected_format:
        validators.append(FormatValidator(
            expected_format=expected_format,
            check_structure=False,
        ))
    
    return CompositeValidator(validators=validators)
