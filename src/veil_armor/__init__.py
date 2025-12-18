"""Veil Armor - LLM Security Framework

A comprehensive security framework for Large Language Models that protects against
prompt injections, jailbreaks, sensitive data leakage, and other security threats.

Built on top of Vigil library: https://github.com/deadbits/vigil-llm
"""

from .core import VeilArmor
from .models import ScanResult, ThreatLevel, ScannerType

__version__ = "1.0.0"
__author__ = "Your Name"
__license__ = "Apache 2.0"

__all__ = [
    "VeilArmor",
    "ScanResult",
    "ThreatLevel",
    "ScannerType",
]
