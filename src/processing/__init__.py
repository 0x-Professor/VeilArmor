"""
VeilArmor v2.0 - Input Processing Module

Provides input validation, preprocessing, and normalization.
"""

from src.processing.validator import (
    InputValidator,
    ValidationResult,
    ValidationRule,
)
from src.processing.preprocessor import (
    InputPreprocessor,
    PreprocessorResult,
)
from src.processing.normalizer import (
    InputNormalizer,
    NormalizerResult,
)
from src.processing.processor import (
    InputProcessor,
    ProcessingResult,
    ProcessingStage,
)


__all__ = [
    # Validator
    "InputValidator",
    "ValidationResult",
    "ValidationRule",
    # Preprocessor
    "InputPreprocessor",
    "PreprocessorResult",
    # Normalizer
    "InputNormalizer",
    "NormalizerResult",
    # Processor
    "InputProcessor",
    "ProcessingResult",
    "ProcessingStage",
]
