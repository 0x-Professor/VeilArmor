"""
VeilArmor v2.0 - Classifiers Module

Provides modular threat classification with parallel execution support.

Includes:
- Input classifiers: Prompt injection, jailbreak, PII, sensitive content, etc.
- Output classifiers: Content safety, PII leakage, hallucination, bias, etc.
"""

from src.classifiers.base import (
    BaseClassifier,
    ClassificationResult,
    ClassifierType,
    register_classifier,
    get_classifier_class,
    list_registered_classifiers,
)
from src.classifiers.manager import ClassifierManager

# Import all input classifiers for registration
from src.classifiers.input import (
    PromptInjectionClassifier,
    JailbreakClassifier,
    PIIDetectorClassifier,
    SensitiveContentClassifier,
    SystemPromptLeakClassifier,
    AdversarialAttackClassifier,
    ToxicityClassifier,
)

# Import all output classifiers for registration
from src.classifiers.output import (
    ContentSafetyClassifier,
    PIILeakageClassifier,
    InjectionCheckClassifier,
    HallucinationClassifier,
    BiasDetectorClassifier,
)

__all__ = [
    # Base
    "BaseClassifier",
    "ClassificationResult",
    "ClassifierType",
    "ClassifierManager",
    "register_classifier",
    "get_classifier_class",
    "list_registered_classifiers",
    # Input classifiers
    "PromptInjectionClassifier",
    "JailbreakClassifier",
    "PIIDetectorClassifier",
    "SensitiveContentClassifier",
    "SystemPromptLeakClassifier",
    "AdversarialAttackClassifier",
    "ToxicityClassifier",
    # Output classifiers
    "ContentSafetyClassifier",
    "PIILeakageClassifier",
    "InjectionCheckClassifier",
    "HallucinationClassifier",
    "BiasDetectorClassifier",
]
