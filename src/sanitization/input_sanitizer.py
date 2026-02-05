"""
VeilArmor v2.0 - Input Sanitizer

Sanitizes user inputs before processing.
"""

from typing import Any, Dict, List, Optional

from src.sanitization.base import (
    BaseSanitizer,
    SanitizerType,
    SanitizationResult,
    BaseSanitizationStrategy,
)
from src.sanitization.strategies import (
    PIIRedactionStrategy,
    InjectionNeutralizationStrategy,
    NormalizationStrategy,
    ToxicityRemovalStrategy,
)


class InputSanitizer(BaseSanitizer):
    """
    Sanitizer for user inputs.
    
    Applies sanitization strategies to clean potentially malicious
    or sensitive content from user inputs before further processing.
    """
    
    def __init__(
        self,
        enable_pii_redaction: bool = True,
        enable_injection_neutralization: bool = True,
        enable_normalization: bool = True,
        enable_toxicity_removal: bool = False,
    ):
        """
        Initialize input sanitizer.
        
        Args:
            enable_pii_redaction: Enable PII redaction
            enable_injection_neutralization: Enable injection neutralization
            enable_normalization: Enable text normalization
            enable_toxicity_removal: Enable toxicity removal
        """
        super().__init__()
        
        # Add strategies based on configuration
        if enable_normalization:
            self.add_strategy(NormalizationStrategy())
        
        if enable_injection_neutralization:
            self.add_strategy(InjectionNeutralizationStrategy())
        
        if enable_pii_redaction:
            self.add_strategy(PIIRedactionStrategy())
        
        if enable_toxicity_removal:
            self.add_strategy(ToxicityRemovalStrategy())
    
    @property
    def name(self) -> str:
        return "input_sanitizer"
    
    @property
    def sanitizer_type(self) -> SanitizerType:
        return SanitizerType.INPUT
    
    def sanitize(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SanitizationResult:
        """
        Sanitize input text.
        
        Args:
            text: Input text to sanitize
            context: Optional context with classification results
            
        Returns:
            SanitizationResult with sanitized text
        """
        if not self.enabled:
            return SanitizationResult(
                original_text=text,
                sanitized_text=text,
                was_modified=False,
            )
        
        # Apply strategies
        sanitized, changes, applied = self._apply_strategies(text, context)
        
        return SanitizationResult(
            original_text=text,
            sanitized_text=sanitized,
            was_modified=text != sanitized,
            changes=changes,
            strategies_applied=applied,
            metadata={
                "sanitizer": self.name,
                "type": self.sanitizer_type.value,
            },
        )
    
    def sanitize_with_classification(
        self,
        text: str,
        classification_results: List[Dict[str, Any]],
    ) -> SanitizationResult:
        """
        Sanitize based on classification results.
        
        Uses classification results to determine what needs sanitization.
        
        Args:
            text: Input text
            classification_results: Results from classifiers
            
        Returns:
            SanitizationResult
        """
        context = {
            "classification_results": classification_results,
            "pii_types": self._extract_pii_types(classification_results),
        }
        
        return self.sanitize(text, context)
    
    def _extract_pii_types(
        self,
        results: List[Dict[str, Any]],
    ) -> List[str]:
        """Extract detected PII types from classification results."""
        pii_types = []
        for result in results:
            if result.get("threat_type") == "data_leakage":
                metadata = result.get("metadata", {})
                pii_types.extend(metadata.get("pii_types", []))
        return list(set(pii_types))


class StrictInputSanitizer(InputSanitizer):
    """
    Strict input sanitizer with all protections enabled.
    """
    
    def __init__(self):
        super().__init__(
            enable_pii_redaction=True,
            enable_injection_neutralization=True,
            enable_normalization=True,
            enable_toxicity_removal=True,
        )
    
    @property
    def name(self) -> str:
        return "strict_input_sanitizer"


class MinimalInputSanitizer(InputSanitizer):
    """
    Minimal input sanitizer with only essential protections.
    """
    
    def __init__(self):
        super().__init__(
            enable_pii_redaction=False,
            enable_injection_neutralization=True,
            enable_normalization=True,
            enable_toxicity_removal=False,
        )
    
    @property
    def name(self) -> str:
        return "minimal_input_sanitizer"
