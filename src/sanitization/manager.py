"""
VeilArmor v2.0 - Sanitization Manager

Orchestrates input and output sanitization with caching and metrics.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.sanitization.base import SanitizationResult, SanitizerType
from src.sanitization.input_sanitizer import (
    InputSanitizer,
    StrictInputSanitizer,
    MinimalInputSanitizer,
)
from src.sanitization.output_sanitizer import (
    OutputSanitizer,
    StrictOutputSanitizer,
    APIOutputSanitizer,
)


@dataclass
class SanitizationMetrics:
    """Metrics for sanitization operations."""
    total_requests: int = 0
    input_sanitizations: int = 0
    output_sanitizations: int = 0
    total_changes: int = 0
    pii_redactions: int = 0
    injection_neutralizations: int = 0
    toxicity_removals: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary."""
        return {
            "total_requests": self.total_requests,
            "input_sanitizations": self.input_sanitizations,
            "output_sanitizations": self.output_sanitizations,
            "total_changes": self.total_changes,
            "pii_redactions": self.pii_redactions,
            "injection_neutralizations": self.injection_neutralizations,
            "toxicity_removals": self.toxicity_removals,
        }


class SanitizationManager:
    """
    Manager for coordinating sanitization operations.
    
    Provides a unified interface for input and output sanitization
    with support for different sanitization modes.
    """
    
    # Predefined sanitizer configurations
    MODES = {
        "strict": {
            "input": StrictInputSanitizer,
            "output": StrictOutputSanitizer,
        },
        "normal": {
            "input": InputSanitizer,
            "output": OutputSanitizer,
        },
        "minimal": {
            "input": MinimalInputSanitizer,
            "output": OutputSanitizer,
        },
        "api": {
            "input": InputSanitizer,
            "output": APIOutputSanitizer,
        },
    }
    
    def __init__(
        self,
        mode: str = "normal",
        custom_input_sanitizer: Optional[InputSanitizer] = None,
        custom_output_sanitizer: Optional[OutputSanitizer] = None,
    ):
        """
        Initialize sanitization manager.
        
        Args:
            mode: Sanitization mode (strict, normal, minimal, api)
            custom_input_sanitizer: Optional custom input sanitizer
            custom_output_sanitizer: Optional custom output sanitizer
        """
        self.mode = mode
        self._metrics = SanitizationMetrics()
        
        # Initialize sanitizers
        if custom_input_sanitizer:
            self.input_sanitizer = custom_input_sanitizer
        elif mode in self.MODES:
            self.input_sanitizer = self.MODES[mode]["input"]()
        else:
            self.input_sanitizer = InputSanitizer()
        
        if custom_output_sanitizer:
            self.output_sanitizer = custom_output_sanitizer
        elif mode in self.MODES:
            self.output_sanitizer = self.MODES[mode]["output"]()
        else:
            self.output_sanitizer = OutputSanitizer()
    
    def sanitize_input(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SanitizationResult:
        """
        Sanitize user input.
        
        Args:
            text: Input text to sanitize
            context: Optional context
            
        Returns:
            SanitizationResult
        """
        self._metrics.total_requests += 1
        
        result = self.input_sanitizer.sanitize(text, context)
        
        if result.was_modified:
            self._metrics.input_sanitizations += 1
            self._update_change_metrics(result.changes)
        
        return result
    
    def sanitize_output(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SanitizationResult:
        """
        Sanitize LLM output.
        
        Args:
            text: Output text to sanitize
            context: Optional context
            
        Returns:
            SanitizationResult
        """
        self._metrics.total_requests += 1
        
        result = self.output_sanitizer.sanitize(text, context)
        
        if result.was_modified:
            self._metrics.output_sanitizations += 1
            self._update_change_metrics(result.changes)
        
        return result
    
    def sanitize_input_with_classification(
        self,
        text: str,
        classification_results: List[Dict[str, Any]],
    ) -> SanitizationResult:
        """
        Sanitize input based on classification results.
        
        Args:
            text: Input text
            classification_results: Classification results
            
        Returns:
            SanitizationResult
        """
        self._metrics.total_requests += 1
        
        result = self.input_sanitizer.sanitize_with_classification(
            text, classification_results
        )
        
        if result.was_modified:
            self._metrics.input_sanitizations += 1
            self._update_change_metrics(result.changes)
        
        return result
    
    def sanitize_output_with_classification(
        self,
        text: str,
        classification_results: List[Dict[str, Any]],
    ) -> SanitizationResult:
        """
        Sanitize output based on classification results.
        
        Args:
            text: Output text
            classification_results: Classification results
            
        Returns:
            SanitizationResult
        """
        self._metrics.total_requests += 1
        
        result = self.output_sanitizer.sanitize_with_classification(
            text, classification_results
        )
        
        if result.was_modified:
            self._metrics.output_sanitizations += 1
            self._update_change_metrics(result.changes)
        
        return result
    
    def sanitize_both(
        self,
        input_text: str,
        output_text: str,
        input_context: Optional[Dict[str, Any]] = None,
        output_context: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """
        Sanitize both input and output.
        
        Args:
            input_text: Input text
            output_text: Output text
            input_context: Context for input sanitization
            output_context: Context for output sanitization
            
        Returns:
            Tuple of (input_result, output_result)
        """
        input_result = self.sanitize_input(input_text, input_context)
        output_result = self.sanitize_output(output_text, output_context)
        
        return input_result, output_result
    
    def _update_change_metrics(self, changes: List[Dict[str, Any]]) -> None:
        """Update metrics based on changes."""
        self._metrics.total_changes += len(changes)
        
        for change in changes:
            change_type = change.get("type", "")
            if change_type == "pii_redaction":
                self._metrics.pii_redactions += 1
            elif change_type == "injection_neutralization":
                self._metrics.injection_neutralizations += 1
            elif change_type == "toxicity_removal":
                self._metrics.toxicity_removals += 1
    
    def set_mode(self, mode: str) -> None:
        """
        Set sanitization mode.
        
        Args:
            mode: New mode (strict, normal, minimal, api)
        """
        if mode not in self.MODES:
            raise ValueError(f"Unknown mode: {mode}")
        
        self.mode = mode
        self.input_sanitizer = self.MODES[mode]["input"]()
        self.output_sanitizer = self.MODES[mode]["output"]()
    
    def enable_input_sanitization(self) -> None:
        """Enable input sanitization."""
        self.input_sanitizer.enable()
    
    def disable_input_sanitization(self) -> None:
        """Disable input sanitization."""
        self.input_sanitizer.disable()
    
    def enable_output_sanitization(self) -> None:
        """Enable output sanitization."""
        self.output_sanitizer.enable()
    
    def disable_output_sanitization(self) -> None:
        """Disable output sanitization."""
        self.output_sanitizer.disable()
    
    def get_metrics(self) -> SanitizationMetrics:
        """Get sanitization metrics."""
        return self._metrics
    
    def reset_metrics(self) -> None:
        """Reset metrics."""
        self._metrics = SanitizationMetrics()
    
    def get_status(self) -> Dict[str, Any]:
        """Get manager status."""
        return {
            "mode": self.mode,
            "input_sanitizer": {
                "name": self.input_sanitizer.name,
                "enabled": self.input_sanitizer.enabled,
                "strategies": [s.name for s in self.input_sanitizer.get_strategies()],
            },
            "output_sanitizer": {
                "name": self.output_sanitizer.name,
                "enabled": self.output_sanitizer.enabled,
                "strategies": [s.name for s in self.output_sanitizer.get_strategies()],
            },
            "metrics": self._metrics.to_dict(),
        }
