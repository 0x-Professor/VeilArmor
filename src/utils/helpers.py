"""
VeilArmor v2.0 - Utility Helpers

This module provides common utility functions used across the VeilArmor framework.
"""

import hashlib
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

import xxhash

T = TypeVar("T")


def generate_correlation_id() -> str:
    """
    Generate a unique correlation ID for request tracing.
    
    Returns:
        Unique correlation ID in format: req-{uuid}
    """
    return f"req-{uuid.uuid4().hex[:12]}-{uuid.uuid4().hex[:12]}"


def generate_session_id() -> str:
    """
    Generate a unique session ID.
    
    Returns:
        Unique session ID in format: sess-{uuid}
    """
    return f"sess-{uuid.uuid4().hex}"


def generate_conversation_id() -> str:
    """
    Generate a unique conversation ID.
    
    Returns:
        Unique conversation ID in format: conv-{uuid}
    """
    return f"conv-{uuid.uuid4().hex}"


def generate_turn_id() -> str:
    """
    Generate a unique turn ID for conversation tracking.
    
    Returns:
        Unique turn ID in format: turn-{uuid}
    """
    return f"turn-{uuid.uuid4().hex[:16]}"


def get_timestamp() -> str:
    """
    Get current UTC timestamp in ISO 8601 format.
    
    Returns:
        ISO 8601 formatted timestamp string
    """
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def get_timestamp_ms() -> int:
    """
    Get current timestamp in milliseconds.
    
    Returns:
        Current timestamp in milliseconds since epoch
    """
    return int(time.time() * 1000)


def compute_hash(data: Union[str, bytes], algorithm: str = "xxhash") -> str:
    """
    Compute hash of data.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm to use (xxhash, sha256, md5)
        
    Returns:
        Hexadecimal hash string
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    
    if algorithm == "xxhash":
        return xxhash.xxh64(data).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(data).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(data).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def compute_cache_key(
    user_id: Optional[str],
    prompt: str,
    model: Optional[str] = None,
    sanitization_level: Optional[str] = None,
    config_version: Optional[str] = None
) -> str:
    """
    Compute cache key from request parameters.
    
    Args:
        user_id: User identifier
        prompt: Normalized prompt text
        model: LLM model name
        sanitization_level: Sanitization level applied
        config_version: Classifier configuration version
        
    Returns:
        Unique cache key hash
    """
    components = [
        user_id or "anonymous",
        prompt,
        model or "default",
        sanitization_level or "none",
        config_version or "v1"
    ]
    key_string = "|".join(components)
    return compute_hash(key_string, "xxhash")


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate text to maximum length with suffix.
    
    Args:
        text: Text to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to append when truncated
        
    Returns:
        Truncated text
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


def mask_sensitive_data(
    text: str,
    patterns: Optional[List[str]] = None,
    mask_char: str = "*"
) -> str:
    """
    Mask sensitive data in text for logging.
    
    Args:
        text: Text containing potentially sensitive data
        patterns: List of regex patterns to mask
        mask_char: Character to use for masking
        
    Returns:
        Text with sensitive data masked
    """
    if patterns is None:
        # Default patterns for common sensitive data
        patterns = [
            r"api[_-]?key[=:]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",  # API keys
            r"sk-[a-zA-Z0-9]{20,}",  # OpenAI keys
            r"password[=:]\s*['\"]?([^'\"\\s]+)['\"]?",  # Passwords
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Emails
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # Phone numbers
            r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",  # SSN
            r"\b\d{13,19}\b",  # Credit card numbers
        ]
    
    masked_text = text
    for pattern in patterns:
        masked_text = re.sub(
            pattern,
            lambda m: mask_char * len(m.group(0)),
            masked_text,
            flags=re.IGNORECASE
        )
    
    return masked_text


def safe_get(
    data: Dict[str, Any],
    key_path: str,
    default: Optional[T] = None,
    separator: str = "."
) -> Optional[T]:
    """
    Safely get nested dictionary value by dot-notation path.
    
    Args:
        data: Dictionary to search
        key_path: Dot-separated path to value
        default: Default value if not found
        separator: Path separator character
        
    Returns:
        Value at path or default
    """
    keys = key_path.split(separator)
    current = data
    
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    
    return current  # type: ignore


def merge_dicts(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge multiple dictionaries.
    
    Args:
        *dicts: Dictionaries to merge (later ones override earlier)
        
    Returns:
        Merged dictionary
    """
    result: Dict[str, Any] = {}
    
    for d in dicts:
        for key, value in d.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = merge_dicts(result[key], value)
            else:
                result[key] = value
    
    return result


def chunk_text(text: str, chunk_size: int, overlap: int = 0) -> List[str]:
    """
    Split text into chunks of specified size with optional overlap.
    
    Args:
        text: Text to chunk
        chunk_size: Size of each chunk in characters
        overlap: Number of overlapping characters between chunks
        
    Returns:
        List of text chunks
    """
    if chunk_size <= 0:
        raise ValueError("Chunk size must be positive")
    if overlap < 0:
        raise ValueError("Overlap must be non-negative")
    if overlap >= chunk_size:
        raise ValueError("Overlap must be less than chunk size")
    
    chunks = []
    start = 0
    step = chunk_size - overlap
    
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunks.append(text[start:end])
        start += step
    
    return chunks


def timing_decorator(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator to measure function execution time.
    
    Args:
        func: Function to wrap
        
    Returns:
        Wrapped function that logs execution time
    """
    import functools
    
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        start_time = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            # Note: actual logging would happen here with proper logger
            _ = elapsed_ms
    
    return wrapper


def async_timing_decorator(func: Callable[..., T]) -> Callable[..., T]:
    """
    Async decorator to measure function execution time.
    
    Args:
        func: Async function to wrap
        
    Returns:
        Wrapped async function that logs execution time
    """
    import functools
    
    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        start_time = time.perf_counter()
        try:
            result = await func(*args, **kwargs)
            return result
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            _ = elapsed_ms
    
    return wrapper  # type: ignore


def clamp(value: float, min_value: float, max_value: float) -> float:
    """
    Clamp a value between minimum and maximum.
    
    Args:
        value: Value to clamp
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        Clamped value
    """
    return max(min_value, min(max_value, value))


def normalize_score(score: float) -> float:
    """
    Normalize a score to range [0.0, 1.0].
    
    Args:
        score: Score value to normalize
        
    Returns:
        Normalized score
    """
    return clamp(score, 0.0, 1.0)


def parse_bool(value: Any) -> bool:
    """
    Parse boolean from various input types.
    
    Args:
        value: Value to parse
        
    Returns:
        Boolean value
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on", "enabled")
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def redact_for_logging(data: Dict[str, Any], sensitive_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Redact sensitive fields from dictionary for safe logging.
    
    Args:
        data: Dictionary containing data
        sensitive_keys: List of keys to redact
        
    Returns:
        Dictionary with sensitive values redacted
    """
    if sensitive_keys is None:
        sensitive_keys = [
            "password", "api_key", "apikey", "secret", "token",
            "authorization", "auth", "credential", "private_key"
        ]
    
    def redact_value(key: str, value: Any) -> Any:
        key_lower = key.lower()
        for sensitive in sensitive_keys:
            if sensitive in key_lower:
                if isinstance(value, str):
                    return "[REDACTED]"
                return "[REDACTED]"
        
        if isinstance(value, dict):
            return {k: redact_value(k, v) for k, v in value.items()}
        elif isinstance(value, list):
            return [redact_value("item", v) for v in value]
        return value
    
    return {k: redact_value(k, v) for k, v in data.items()}


def format_bytes(size: int) -> str:
    """
    Format byte size to human-readable string.
    
    Args:
        size: Size in bytes
        
    Returns:
        Human-readable size string
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0  # type: ignore
    return f"{size:.2f} PB"


def format_duration_ms(duration_ms: float) -> str:
    """
    Format duration in milliseconds to human-readable string.
    
    Args:
        duration_ms: Duration in milliseconds
        
    Returns:
        Human-readable duration string
    """
    if duration_ms < 1:
        return f"{duration_ms * 1000:.2f}us"
    elif duration_ms < 1000:
        return f"{duration_ms:.2f}ms"
    elif duration_ms < 60000:
        return f"{duration_ms / 1000:.2f}s"
    else:
        minutes = int(duration_ms / 60000)
        seconds = (duration_ms % 60000) / 1000
        return f"{minutes}m {seconds:.2f}s"
