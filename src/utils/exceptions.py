"""
VeilArmor - Custom Exceptions

This module defines all custom exceptions used throughout the VeilArmor framework.
Each exception includes contextual information for debugging and logging.
"""

from typing import Any, Dict, List, Optional


class VeilArmorException(Exception):
    """Base exception for all VeilArmor errors."""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None
    ) -> None:
        """
        Initialize VeilArmor exception.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code
            details: Additional context about the error
            correlation_id: Request correlation ID for tracing
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code or "VEILARMOR_ERROR"
        self.details = details or {}
        self.correlation_id = correlation_id
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses."""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details,
            "correlation_id": self.correlation_id
        }


# Backward compatibility aliases
VeilArmorError = VeilArmorException


# =============================================================================
# Input Processing Exceptions
# =============================================================================

class InputValidationError(VeilArmorException):
    """Raised when input validation fails."""
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"field": field, "value": str(value)[:100] if value else None})
        super().__init__(message, error_code="INPUT_VALIDATION_ERROR", details=details, **kwargs)


class ContentTooLargeError(VeilArmorException):
    """Raised when input content exceeds size limits."""
    
    def __init__(
        self,
        message: str,
        size: int,
        max_size: int,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"size": size, "max_size": max_size})
        super().__init__(message, error_code="CONTENT_TOO_LARGE", details=details, **kwargs)


class EncodingError(VeilArmorException):
    """Raised when character encoding is invalid."""
    
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, error_code="ENCODING_ERROR", **kwargs)


class PreprocessingError(VeilArmorException):
    """Raised when preprocessing fails."""
    
    def __init__(self, message: str, stage: Optional[str] = None, **kwargs: Any) -> None:
        details = kwargs.pop("details", {})
        details.update({"stage": stage})
        super().__init__(message, error_code="PREPROCESSING_ERROR", details=details, **kwargs)


# =============================================================================
# Classification Exceptions
# =============================================================================

class ClassificationError(VeilArmorException):
    """Raised when classification fails."""
    
    def __init__(
        self,
        message: str,
        classifier_name: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"classifier": classifier_name})
        super().__init__(message, error_code="CLASSIFICATION_ERROR", details=details, **kwargs)


class ClassifierNotFoundError(VeilArmorException):
    """Raised when a requested classifier is not found."""
    
    def __init__(self, classifier_name: str, **kwargs: Any) -> None:
        message = f"Classifier not found: {classifier_name}"
        details = kwargs.pop("details", {})
        details.update({"classifier": classifier_name})
        super().__init__(message, error_code="CLASSIFIER_NOT_FOUND", details=details, **kwargs)


class ClassifierTimeoutError(VeilArmorException):
    """Raised when classifier execution times out."""
    
    def __init__(
        self,
        classifier_name: str,
        timeout: float,
        **kwargs: Any
    ) -> None:
        message = f"Classifier '{classifier_name}' timed out after {timeout}s"
        details = kwargs.pop("details", {})
        details.update({"classifier": classifier_name, "timeout_seconds": timeout})
        super().__init__(message, error_code="CLASSIFIER_TIMEOUT", details=details, **kwargs)


# =============================================================================
# Decision Engine Exceptions
# =============================================================================

class DecisionError(VeilArmorException):
    """Raised when decision engine fails."""
    
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, error_code="DECISION_ERROR", **kwargs)


class ThresholdConfigError(VeilArmorException):
    """Raised when threshold configuration is invalid."""
    
    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, error_code="THRESHOLD_CONFIG_ERROR", **kwargs)


# =============================================================================
# Sanitization Exceptions
# =============================================================================

class SanitizationError(VeilArmorException):
    """Raised when sanitization fails."""
    
    def __init__(
        self,
        message: str,
        strategy: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"strategy": strategy})
        super().__init__(message, error_code="SANITIZATION_ERROR", details=details, **kwargs)


class PatternError(VeilArmorException):
    """Raised when pattern matching fails."""
    
    def __init__(
        self,
        message: str,
        pattern: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"pattern": pattern[:100] if pattern else None})
        super().__init__(message, error_code="PATTERN_ERROR", details=details, **kwargs)


# =============================================================================
# LLM Provider Exceptions
# =============================================================================

class LLMError(VeilArmorException):
    """Base exception for LLM provider errors."""
    
    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"provider": provider})
        super().__init__(message, error_code="LLM_PROVIDER_ERROR", details=details, **kwargs)


# Alias for backward compatibility
LLMProviderError = LLMError


class ProviderNotFoundError(LLMError):
    """Raised when LLM provider is not found."""
    
    def __init__(self, provider: str, **kwargs: Any) -> None:
        message = f"LLM provider not found: {provider}"
        super().__init__(message, provider=provider, **kwargs)
        self.error_code = "PROVIDER_NOT_FOUND"


class ProviderAuthError(LLMError):
    """Raised when LLM provider authentication fails."""
    
    def __init__(self, provider: str, **kwargs: Any) -> None:
        message = f"Authentication failed for provider: {provider}"
        super().__init__(message, provider=provider, **kwargs)
        self.error_code = "PROVIDER_AUTH_ERROR"


class ProviderRateLimitError(LLMError):
    """Raised when LLM provider rate limit is exceeded."""
    
    def __init__(
        self,
        provider: str,
        retry_after: Optional[float] = None,
        **kwargs: Any
    ) -> None:
        message = f"Rate limit exceeded for provider: {provider}"
        details = kwargs.pop("details", {})
        details.update({"retry_after_seconds": retry_after})
        super().__init__(message, provider=provider, details=details, **kwargs)
        self.error_code = "PROVIDER_RATE_LIMIT"
        self.retry_after = retry_after


class ProviderTimeoutError(LLMError):
    """Raised when LLM provider request times out."""
    
    def __init__(
        self,
        provider: str,
        timeout: float,
        **kwargs: Any
    ) -> None:
        message = f"Request to provider '{provider}' timed out after {timeout}s"
        details = kwargs.pop("details", {})
        details.update({"timeout_seconds": timeout})
        super().__init__(message, provider=provider, details=details, **kwargs)
        self.error_code = "PROVIDER_TIMEOUT"


class AllProvidersFailedError(LLMError):
    """Raised when all LLM providers fail."""
    
    def __init__(
        self,
        providers: List[str],
        errors: Optional[Dict[str, str]] = None,
        **kwargs: Any
    ) -> None:
        message = f"All LLM providers failed: {', '.join(providers)}"
        details = kwargs.pop("details", {})
        details.update({"providers": providers, "errors": errors or {}})
        super().__init__(message, details=details, **kwargs)
        self.error_code = "ALL_PROVIDERS_FAILED"


# =============================================================================
# Cache Exceptions
# =============================================================================

class CacheError(VeilArmorException):
    """Raised when cache operation fails."""
    
    def __init__(
        self,
        message: str,
        backend: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"backend": backend, "operation": operation})
        super().__init__(message, error_code="CACHE_ERROR", details=details, **kwargs)


class CacheConnectionError(CacheError):
    """Raised when cache connection fails."""
    
    def __init__(self, backend: str, **kwargs: Any) -> None:
        message = f"Failed to connect to cache backend: {backend}"
        super().__init__(message, backend=backend, **kwargs)
        self.error_code = "CACHE_CONNECTION_ERROR"


# =============================================================================
# Conversation Exceptions
# =============================================================================

class ConversationError(VeilArmorException):
    """Raised when conversation operation fails."""
    
    def __init__(
        self,
        message: str,
        conversation_id: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"conversation_id": conversation_id})
        super().__init__(message, error_code="CONVERSATION_ERROR", details=details, **kwargs)


class ConversationNotFoundError(ConversationError):
    """Raised when conversation is not found."""
    
    def __init__(self, conversation_id: str, **kwargs: Any) -> None:
        message = f"Conversation not found: {conversation_id}"
        super().__init__(message, conversation_id=conversation_id, **kwargs)
        self.error_code = "CONVERSATION_NOT_FOUND"


class ConversationBacktrackError(ConversationError):
    """Raised when conversation backtracking fails."""
    
    def __init__(
        self,
        conversation_id: str,
        turn_id: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        message = f"Failed to backtrack conversation: {conversation_id}"
        details = kwargs.pop("details", {})
        details.update({"turn_id": turn_id})
        super().__init__(message, conversation_id=conversation_id, details=details, **kwargs)
        self.error_code = "CONVERSATION_BACKTRACK_ERROR"


# =============================================================================
# Configuration Exceptions
# =============================================================================

class ConfigurationError(VeilArmorException):
    """Raised when configuration is invalid."""
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"config_key": config_key})
        super().__init__(message, error_code="CONFIGURATION_ERROR", details=details, **kwargs)


class SecretNotFoundError(ConfigurationError):
    """Raised when a required secret is not found."""
    
    def __init__(self, secret_name: str, **kwargs: Any) -> None:
        message = f"Required secret not found: {secret_name}"
        super().__init__(message, config_key=secret_name, **kwargs)
        self.error_code = "SECRET_NOT_FOUND"


# =============================================================================
# API / Gateway Exceptions
# =============================================================================

class APIError(VeilArmorException):
    """Base exception for API errors."""
    
    def __init__(
        self,
        message: str,
        status_code: int = 500,
        **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)
        self.status_code = status_code


class AuthenticationError(APIError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs: Any) -> None:
        super().__init__(message, status_code=401, **kwargs)
        self.error_code = "AUTHENTICATION_ERROR"


class AuthorizationError(APIError):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Not authorized", **kwargs: Any) -> None:
        super().__init__(message, status_code=403, **kwargs)
        self.error_code = "AUTHORIZATION_ERROR"


class RateLimitExceededError(APIError):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"retry_after_seconds": retry_after})
        super().__init__(message, status_code=429, details=details, **kwargs)
        self.error_code = "RATE_LIMIT_EXCEEDED"
        self.retry_after = retry_after


class RequestBlockedError(APIError):
    """Raised when request is blocked by security checks."""
    
    def __init__(
        self,
        message: str = "Request blocked due to security concerns",
        threat_type: Optional[str] = None,
        severity: Optional[float] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"threat_type": threat_type, "severity": severity})
        super().__init__(message, status_code=403, details=details, **kwargs)
        self.error_code = "REQUEST_BLOCKED"


# =============================================================================
# Pipeline Exceptions
# =============================================================================

class PipelineError(VeilArmorException):
    """Raised when pipeline execution fails."""
    
    def __init__(
        self,
        message: str,
        stage: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        details = kwargs.pop("details", {})
        details.update({"stage": stage})
        super().__init__(message, error_code="PIPELINE_ERROR", details=details, **kwargs)


class PipelineStageError(PipelineError):
    """Raised when a specific pipeline stage fails."""
    
    def __init__(
        self,
        stage: str,
        cause: Optional[Exception] = None,
        **kwargs: Any
    ) -> None:
        message = f"Pipeline stage '{stage}' failed"
        if cause:
            message += f": {str(cause)}"
        super().__init__(message, stage=stage, **kwargs)
        self.cause = cause