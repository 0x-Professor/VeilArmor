"""
VeilArmor v2.0 - Sanitization Module

Input and output sanitization with strategy-based approach.
"""

from src.sanitization.base import (
    BaseSanitizer,
    BaseSanitizationStrategy,
    SanitizationResult,
    SanitizerType,
)
from src.sanitization.strategies import (
    PIIRedactionStrategy,
    ToxicityRemovalStrategy,
    InjectionNeutralizationStrategy,
    NormalizationStrategy,
    HTMLEscapeStrategy,
    MaskingStrategy,
)
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
from src.sanitization.manager import (
    SanitizationManager,
    SanitizationMetrics,
)


__all__ = [
    # Base classes
    "BaseSanitizer",
    "BaseSanitizationStrategy",
    "SanitizationResult",
    "SanitizerType",
    # Strategies
    "PIIRedactionStrategy",
    "ToxicityRemovalStrategy",
    "InjectionNeutralizationStrategy",
    "NormalizationStrategy",
    "HTMLEscapeStrategy",
    "MaskingStrategy",
    # Input sanitizers
    "InputSanitizer",
    "StrictInputSanitizer",
    "MinimalInputSanitizer",
    # Output sanitizers
    "OutputSanitizer",
    "StrictOutputSanitizer",
    "APIOutputSanitizer",
    # Manager
    "SanitizationManager",
    "SanitizationMetrics",
]
