"""
VeilArmor v2.0 - Validation Engine

Central engine for orchestrating response validation.
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Callable

from src.validation.rules import RuleViolation, RuleSeverity, RuleCategory
from src.validation.validators import (
    BaseValidator,
    ValidatorResult,
    ValidationStatus,
    CompositeValidator,
    QualityValidator,
    SafetyValidator,
    ContentValidator,
    FormatValidator,
    create_default_validator,
    create_strict_validator,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ValidationMode(str, Enum):
    """Validation mode."""
    STRICT = "strict"      # All rules, fail on any error
    NORMAL = "normal"      # Standard rules
    MINIMAL = "minimal"    # Only critical rules
    CUSTOM = "custom"      # Custom configuration


@dataclass
class ValidationResult:
    """Complete validation result."""
    is_valid: bool
    status: ValidationStatus
    violations: List[RuleViolation] = field(default_factory=list)
    validator_results: List[ValidatorResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def error_count(self) -> int:
        """Count error-level violations."""
        return len([
            v for v in self.violations
            if v.severity in (RuleSeverity.ERROR, RuleSeverity.CRITICAL)
        ])
    
    @property
    def warning_count(self) -> int:
        """Count warnings."""
        return len([
            v for v in self.violations
            if v.severity == RuleSeverity.WARNING
        ])
    
    @property
    def critical_count(self) -> int:
        """Count critical violations."""
        return len([
            v for v in self.violations
            if v.severity == RuleSeverity.CRITICAL
        ])
    
    def get_violations_by_category(
        self,
        category: RuleCategory,
    ) -> List[RuleViolation]:
        """Get violations for a category."""
        return [v for v in self.violations if v.category == category]
    
    def get_violations_by_severity(
        self,
        severity: RuleSeverity,
    ) -> List[RuleViolation]:
        """Get violations by severity."""
        return [v for v in self.violations if v.severity == severity]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_valid": self.is_valid,
            "status": self.status.value,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "critical_count": self.critical_count,
            "violations": [
                {
                    "rule_id": v.rule_id,
                    "rule_name": v.rule_name,
                    "category": v.category.value,
                    "severity": v.severity.value,
                    "message": v.message,
                }
                for v in self.violations
            ],
            "duration_ms": self.total_duration_ms,
        }


@dataclass
class ValidationReport:
    """Detailed validation report."""
    content_preview: str
    result: ValidationResult
    timestamp: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content_preview": self.content_preview[:200] + "..." if len(self.content_preview) > 200 else self.content_preview,
            "result": self.result.to_dict(),
            "timestamp": self.timestamp,
            "context": self.context,
        }


class ValidationEngine:
    """
    Central validation engine.
    
    Features:
    - Multiple validation modes
    - Parallel validator execution
    - Customizable validator chain
    - Detailed reporting
    - Callback support
    """
    
    def __init__(
        self,
        mode: ValidationMode = ValidationMode.NORMAL,
        validators: List[BaseValidator] = None,
        fail_fast: bool = False,
        on_violation: Optional[Callable[[RuleViolation], None]] = None,
    ):
        """
        Initialize validation engine.
        
        Args:
            mode: Validation mode
            validators: Custom validators
            fail_fast: Stop on first error
            on_violation: Callback for violations
        """
        self.mode = mode
        self.fail_fast = fail_fast
        self.on_violation = on_violation
        
        # Initialize validators based on mode
        if validators:
            self.validators = validators
        else:
            self.validators = self._create_validators_for_mode(mode)
        
        # Metrics
        self._validations_total = 0
        self._validations_passed = 0
        self._validations_failed = 0
        self._total_violations = 0
        
        logger.info(
            "Validation engine initialized",
            mode=mode.value,
            validator_count=len(self.validators),
        )
    
    def _create_validators_for_mode(
        self,
        mode: ValidationMode,
    ) -> List[BaseValidator]:
        """Create validators for a mode."""
        if mode == ValidationMode.STRICT:
            return [create_strict_validator()]
        elif mode == ValidationMode.MINIMAL:
            return [
                SafetyValidator(
                    check_pii=True,
                    check_credentials=True,
                    check_harmful=False,
                ),
            ]
        else:  # NORMAL
            return [create_default_validator()]
    
    async def validate(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidationResult:
        """
        Validate content.
        
        Args:
            content: Content to validate
            context: Additional context
            
        Returns:
            Validation result
        """
        start_time = time.time()
        context = context or {}
        
        all_violations: List[RuleViolation] = []
        validator_results: List[ValidatorResult] = []
        
        # Run validators
        for validator in self.validators:
            if not validator.enabled:
                continue
            
            try:
                result = await validator.validate(content, context)
                validator_results.append(result)
                
                for violation in result.violations:
                    all_violations.append(violation)
                    
                    # Callback
                    if self.on_violation:
                        self.on_violation(violation)
                
                # Check fail-fast
                if self.fail_fast and result.status == ValidationStatus.FAILED:
                    break
                    
            except Exception as e:
                logger.error(
                    "Validator error",
                    validator=validator.name,
                    error=str(e),
                )
        
        # Determine overall status
        is_valid = all(
            r.status != ValidationStatus.FAILED
            for r in validator_results
        )
        
        if not all_violations:
            status = ValidationStatus.PASSED
        elif any(v.severity in (RuleSeverity.ERROR, RuleSeverity.CRITICAL) for v in all_violations):
            status = ValidationStatus.FAILED
        else:
            status = ValidationStatus.WARNING
        
        total_duration_ms = (time.time() - start_time) * 1000
        
        # Update metrics
        self._validations_total += 1
        self._total_violations += len(all_violations)
        
        if is_valid:
            self._validations_passed += 1
        else:
            self._validations_failed += 1
        
        result = ValidationResult(
            is_valid=is_valid,
            status=status,
            violations=all_violations,
            validator_results=validator_results,
            total_duration_ms=total_duration_ms,
        )
        
        logger.debug(
            "Validation complete",
            is_valid=is_valid,
            violations=len(all_violations),
            duration_ms=total_duration_ms,
        )
        
        return result
    
    async def validate_with_report(
        self,
        content: str,
        context: Dict[str, Any] = None,
    ) -> ValidationReport:
        """
        Validate content and generate detailed report.
        
        Args:
            content: Content to validate
            context: Additional context
            
        Returns:
            Validation report
        """
        result = await self.validate(content, context)
        
        return ValidationReport(
            content_preview=content[:500] if len(content) > 500 else content,
            result=result,
            context=context or {},
        )
    
    async def validate_batch(
        self,
        contents: List[str],
        context: Dict[str, Any] = None,
    ) -> List[ValidationResult]:
        """
        Validate multiple contents.
        
        Args:
            contents: List of contents
            context: Shared context
            
        Returns:
            List of validation results
        """
        tasks = [self.validate(content, context) for content in contents]
        return await asyncio.gather(*tasks)
    
    def add_validator(self, validator: BaseValidator) -> None:
        """Add a validator."""
        self.validators.append(validator)
        logger.debug("Validator added", validator=validator.name)
    
    def remove_validator(self, name: str) -> bool:
        """Remove a validator by name."""
        for i, v in enumerate(self.validators):
            if v.name == name:
                del self.validators[i]
                logger.debug("Validator removed", validator=name)
                return True
        return False
    
    def set_mode(self, mode: ValidationMode) -> None:
        """Change validation mode."""
        self.mode = mode
        self.validators = self._create_validators_for_mode(mode)
        logger.info("Validation mode changed", mode=mode.value)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        return {
            "mode": self.mode.value,
            "validator_count": len(self.validators),
            "validations_total": self._validations_total,
            "validations_passed": self._validations_passed,
            "validations_failed": self._validations_failed,
            "total_violations": self._total_violations,
            "pass_rate": (
                self._validations_passed / self._validations_total
                if self._validations_total > 0 else 0
            ),
        }


# ---------------------------------------------------------------------
# Factory Functions
# ---------------------------------------------------------------------

def create_validation_engine(
    mode: str = "normal",
    **kwargs,
) -> ValidationEngine:
    """
    Create a validation engine.
    
    Args:
        mode: Validation mode (strict, normal, minimal)
        **kwargs: Additional configuration
        
    Returns:
        Configured validation engine
    """
    mode_enum = ValidationMode(mode.lower())
    return ValidationEngine(mode=mode_enum, **kwargs)


def create_custom_engine(
    check_safety: bool = True,
    check_quality: bool = True,
    check_format: bool = False,
    expected_format: str = None,
    blocked_phrases: List[str] = None,
    max_length: int = 100000,
    fail_fast: bool = False,
) -> ValidationEngine:
    """
    Create a custom validation engine.
    
    Args:
        check_safety: Enable safety checks
        check_quality: Enable quality checks
        check_format: Enable format checks
        expected_format: Expected format
        blocked_phrases: Blocked phrases
        max_length: Maximum length
        fail_fast: Stop on first error
        
    Returns:
        Custom validation engine
    """
    validators = []
    
    if check_safety:
        validators.append(SafetyValidator())
    
    if check_quality:
        validators.append(QualityValidator(max_length=max_length))
    
    if check_format or expected_format:
        validators.append(FormatValidator(
            expected_format=expected_format,
        ))
    
    if blocked_phrases:
        validators.append(ContentValidator(
            blocked_phrases=blocked_phrases,
        ))
    
    return ValidationEngine(
        mode=ValidationMode.CUSTOM,
        validators=validators,
        fail_fast=fail_fast,
    )


# ---------------------------------------------------------------------
# Quick Validation Functions
# ---------------------------------------------------------------------

async def quick_validate(
    content: str,
    mode: str = "normal",
) -> bool:
    """
    Quick validation check.
    
    Args:
        content: Content to validate
        mode: Validation mode
        
    Returns:
        True if valid
    """
    engine = create_validation_engine(mode)
    result = await engine.validate(content)
    return result.is_valid


async def validate_for_safety(content: str) -> ValidationResult:
    """
    Validate content for safety only.
    
    Args:
        content: Content to check
        
    Returns:
        Validation result
    """
    engine = ValidationEngine(
        mode=ValidationMode.CUSTOM,
        validators=[SafetyValidator()],
    )
    return await engine.validate(content)


async def validate_for_pii(content: str) -> List[RuleViolation]:
    """
    Check content for PII.
    
    Args:
        content: Content to check
        
    Returns:
        List of PII violations
    """
    from src.validation.rules import SafetyRule
    
    rule = SafetyRule(
        check_pii=True,
        check_credentials=False,
        check_harmful=False,
    )
    
    return rule.validate(content)
