"""Custom exceptions for VeilArmor"""


class VeilArmorError(Exception):
    """Base exception for VeilArmor"""
    pass


class ClassificationError(VeilArmorError):
    """Error during threat classification"""
    pass


class SanitizationError(VeilArmorError):
    """Error during text sanitization"""
    pass


class LLMError(VeilArmorError):
    """Error communicating with LLM"""
    pass


class ConfigurationError(VeilArmorError):
    """Error in configuration"""
    pass