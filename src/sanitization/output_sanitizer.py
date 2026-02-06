"""
VeilArmor - Output Sanitizer

Sanitizes LLM outputs before returning to users.
"""

import re
from typing import Any, Dict, List, Optional

from src.sanitization.base import (
    BaseSanitizer,
    SanitizerType,
    SanitizationResult,
    BaseSanitizationStrategy,
    SanitizationStrategy,
)
from src.sanitization.strategies import (
    PIIRedactionStrategy,
    ToxicityRemovalStrategy,
    HTMLEscapeStrategy,
)


class HallucinationMarkerStrategy(BaseSanitizationStrategy):
    """
    Strategy for marking potential hallucinations in output.
    """
    
    # Patterns that might indicate hallucinated content
    HALLUCINATION_INDICATORS = [
        (r"(?:according\s+to\s+(?:a\s+)?\d{4}\s+(?:study|report|article))", "[VERIFY: "),
        (r"(?:(?:Dr\.|Professor)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\s+(?:at|from)\s+)", "[VERIFY: "),
        (r"(?:statistics?\s+show|research\s+(?:shows?|proves?))", "[VERIFY: "),
    ]
    
    @property
    def name(self) -> str:
        return "hallucination_marker"
    
    @property
    def strategy_type(self) -> SanitizationStrategy:
        return SanitizationStrategy.TRANSFORM
    
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """Add verification markers to potential hallucinations."""
        changes = []
        result = text
        
        # Only apply if context indicates hallucination detection
        if not context or not context.get("hallucination_detected"):
            return result, changes
        
        for pattern, prefix in self.HALLUCINATION_INDICATORS:
            matches = list(re.finditer(pattern, result, re.IGNORECASE))
            for match in reversed(matches):
                # Find the end of the sentence
                sentence_end = result.find('.', match.end())
                if sentence_end == -1:
                    sentence_end = len(result)
                
                # Wrap the claim
                claim = result[match.start():sentence_end + 1]
                wrapped = f"{prefix}{claim}]"
                result = result[:match.start()] + wrapped + result[sentence_end + 1:]
                
                changes.append({
                    "type": "hallucination_marker",
                    "position": match.start(),
                })
        
        return result, changes


class BiasDisclaimerStrategy(BaseSanitizationStrategy):
    """
    Strategy for adding bias disclaimers to output.
    """
    
    DISCLAIMER = "\n\n[Note: This response may contain generalizations. Individual experiences may vary.]"
    
    @property
    def name(self) -> str:
        return "bias_disclaimer"
    
    @property
    def strategy_type(self) -> SanitizationStrategy:
        return SanitizationStrategy.TRANSFORM
    
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """Add bias disclaimer if bias detected."""
        changes = []
        result = text
        
        if context and context.get("bias_detected"):
            result = text + self.DISCLAIMER
            changes.append({
                "type": "bias_disclaimer",
                "position": len(text),
            })
        
        return result, changes


class OutputSanitizer(BaseSanitizer):
    """
    Sanitizer for LLM outputs.
    
    Applies sanitization strategies to clean LLM responses
    before returning them to users.
    """
    
    def __init__(
        self,
        enable_pii_redaction: bool = True,
        enable_toxicity_removal: bool = True,
        enable_html_escape: bool = False,
        enable_hallucination_markers: bool = True,
        enable_bias_disclaimers: bool = True,
    ):
        """
        Initialize output sanitizer.
        
        Args:
            enable_pii_redaction: Enable PII redaction
            enable_toxicity_removal: Enable toxicity removal
            enable_html_escape: Enable HTML escaping
            enable_hallucination_markers: Enable hallucination markers
            enable_bias_disclaimers: Enable bias disclaimers
        """
        super().__init__()
        
        # Add strategies based on configuration
        if enable_pii_redaction:
            self.add_strategy(PIIRedactionStrategy())
        
        if enable_toxicity_removal:
            self.add_strategy(ToxicityRemovalStrategy())
        
        if enable_html_escape:
            self.add_strategy(HTMLEscapeStrategy())
        
        if enable_hallucination_markers:
            self.add_strategy(HallucinationMarkerStrategy())
        
        if enable_bias_disclaimers:
            self.add_strategy(BiasDisclaimerStrategy())
    
    @property
    def name(self) -> str:
        return "output_sanitizer"
    
    @property
    def sanitizer_type(self) -> SanitizerType:
        return SanitizerType.OUTPUT
    
    def sanitize(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SanitizationResult:
        """
        Sanitize LLM output.
        
        Args:
            text: LLM output text
            context: Optional context with classification results
            
        Returns:
            SanitizationResult with sanitized output
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
        
        Args:
            text: LLM output text
            classification_results: Results from output classifiers
            
        Returns:
            SanitizationResult
        """
        context = {
            "classification_results": classification_results,
            "hallucination_detected": self._has_threat_type(
                classification_results, "hallucination"
            ),
            "bias_detected": self._has_threat_type(
                classification_results, "bias"
            ),
            "pii_types": self._extract_pii_types(classification_results),
        }
        
        return self.sanitize(text, context)
    
    def _has_threat_type(
        self,
        results: List[Dict[str, Any]],
        threat_type: str,
    ) -> bool:
        """Check if results contain a specific threat type with significant severity."""
        for result in results:
            if result.get("threat_type") == threat_type:
                if result.get("severity", 0) >= 0.4:
                    return True
        return False
    
    def _extract_pii_types(
        self,
        results: List[Dict[str, Any]],
    ) -> List[str]:
        """Extract detected PII types from results."""
        pii_types = []
        for result in results:
            if result.get("threat_type") == "data_leakage":
                metadata = result.get("metadata", {})
                pii_types.extend(metadata.get("pii_types", []))
        return list(set(pii_types))


class StrictOutputSanitizer(OutputSanitizer):
    """
    Strict output sanitizer with all protections enabled.
    """
    
    def __init__(self):
        super().__init__(
            enable_pii_redaction=True,
            enable_toxicity_removal=True,
            enable_html_escape=True,
            enable_hallucination_markers=True,
            enable_bias_disclaimers=True,
        )
    
    @property
    def name(self) -> str:
        return "strict_output_sanitizer"


class APIOutputSanitizer(OutputSanitizer):
    """
    Output sanitizer optimized for API responses (with HTML escaping).
    """
    
    def __init__(self):
        super().__init__(
            enable_pii_redaction=True,
            enable_toxicity_removal=True,
            enable_html_escape=True,
            enable_hallucination_markers=False,
            enable_bias_disclaimers=False,
        )
    
    @property
    def name(self) -> str:
        return "api_output_sanitizer"
