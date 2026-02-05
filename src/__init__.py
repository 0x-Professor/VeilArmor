"""
VeilArmor v2.0 - Enterprise LLM Security Framework

A production-ready, modular security framework providing multi-layered protection
against prompt injections, jailbreaks, PII leakage, adversarial attacks, and
sophisticated security threats targeting Large Language Models.

Architecture Layers:
    1. API Gateway - Request validation, auth, rate limiting
    2. Input Processing - Validation, preprocessing, normalization
    3. Classification Engine - Parallel threat classification
    4. Decision Engine - Scoring and action determination
    5. Sanitization Layer - Score-based input sanitization
    6. LLM Provider Layer - Multi-provider LLM integration
    7. Output Validation - Response safety checks
    8. Output Sanitization - Response cleaning and formatting
    9. Conversation Management - Multi-turn tracking and backtracking

Copyright (c) 2026 VeilArmor
License: MIT
"""

__version__ = "2.0.0"
__author__ = "VeilArmor Team"
__license__ = "MIT"

from typing import Final

# Package metadata
PACKAGE_NAME: Final[str] = "veilarmor"
VERSION: Final[str] = __version__

# Layer identifiers for logging
class Layers:
    """Layer identifiers for structured logging."""
    API_GATEWAY: Final[str] = "API_GATEWAY"
    INPUT_PROCESSING: Final[str] = "INPUT_PROCESSING"
    CLASSIFICATION_ENGINE: Final[str] = "CLASSIFICATION_ENGINE"
    DECISION_ENGINE: Final[str] = "DECISION_ENGINE"
    SANITIZATION: Final[str] = "SANITIZATION"
    LLM_PROVIDER: Final[str] = "LLM_PROVIDER"
    OUTPUT_VALIDATION: Final[str] = "OUTPUT_VALIDATION"
    OUTPUT_SANITIZATION: Final[str] = "OUTPUT_SANITIZATION"
    CONVERSATION: Final[str] = "CONVERSATION"
    CACHE: Final[str] = "CACHE"


# Action types
class Actions:
    """Decision action types."""
    BLOCK: Final[str] = "BLOCK"
    SANITIZE: Final[str] = "SANITIZE"
    ALLOW: Final[str] = "ALLOW"


# Threat types
class ThreatTypes:
    """Threat type identifiers."""
    PROMPT_INJECTION: Final[str] = "PROMPT_INJECTION"
    JAILBREAK: Final[str] = "JAILBREAK"
    PII_EXPOSURE: Final[str] = "PII_EXPOSURE"
    SENSITIVE_CONTENT: Final[str] = "SENSITIVE_CONTENT"
    SYSTEM_PROMPT_LEAK: Final[str] = "SYSTEM_PROMPT_LEAK"
    ADVERSARIAL_ATTACK: Final[str] = "ADVERSARIAL_ATTACK"
    TOXICITY: Final[str] = "TOXICITY"
    TOXIC_CONTENT: Final[str] = "TOXIC_CONTENT"
    CONTENT_SAFETY: Final[str] = "CONTENT_SAFETY"
    PII_LEAKAGE: Final[str] = "PII_LEAKAGE"
    DATA_LEAKAGE: Final[str] = "DATA_LEAKAGE"
    HARMFUL_CONTENT: Final[str] = "HARMFUL_CONTENT"
    INJECTION_OUTPUT: Final[str] = "INJECTION_OUTPUT"
    HALLUCINATION: Final[str] = "HALLUCINATION"
    BIAS: Final[str] = "BIAS"