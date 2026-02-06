"""
VeilArmor - Correlation ID Management

Manages correlation IDs for request tracing across all layers.
Uses contextvars for async-safe correlation ID propagation.
"""

import contextvars
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Optional

# Context variable for correlation ID - thread/async-safe
_correlation_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "correlation_id", default=None
)

# Context variable for full request context
_request_context_var: contextvars.ContextVar[Optional["CorrelationContext"]] = contextvars.ContextVar(
    "request_context", default=None
)


def generate_correlation_id() -> str:
    """
    Generate a unique correlation ID.
    
    Returns:
        Unique correlation ID in format: req-{hex}-{hex}
    """
    return f"req-{uuid.uuid4().hex[:12]}-{uuid.uuid4().hex[:12]}"


def get_correlation_id() -> Optional[str]:
    """
    Get the current correlation ID from context.
    
    Returns:
        Current correlation ID or None if not set
    """
    return _correlation_id_var.get()


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """
    Set the correlation ID in context.
    
    Args:
        correlation_id: Correlation ID to set, or None to generate new one
        
    Returns:
        The correlation ID that was set
    """
    if correlation_id is None:
        correlation_id = generate_correlation_id()
    _correlation_id_var.set(correlation_id)
    return correlation_id


def clear_correlation_id() -> None:
    """Clear the correlation ID from context."""
    _correlation_id_var.set(None)


@dataclass
class CorrelationContext:
    """
    Full request context for logging and tracing.
    
    Attributes:
        correlation_id: Unique request correlation ID
        user_id: User identifier
        session_id: Session identifier
        conversation_id: Conversation identifier (if applicable)
        start_time: Request start timestamp
        metadata: Additional context metadata
    """
    
    correlation_id: str = field(default_factory=generate_correlation_id)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    conversation_id: Optional[str] = None
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def elapsed_ms(self) -> float:
        """Calculate elapsed time in milliseconds since context creation."""
        delta = datetime.now(timezone.utc) - self.start_time
        return delta.total_seconds() * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for logging."""
        return {
            "correlation_id": self.correlation_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "conversation_id": self.conversation_id,
            "start_time": self.start_time.isoformat(),
            "elapsed_ms": self.elapsed_ms,
            **self.metadata
        }
    
    def with_metadata(self, **kwargs: Any) -> "CorrelationContext":
        """Create new context with additional metadata."""
        new_metadata = {**self.metadata, **kwargs}
        return CorrelationContext(
            correlation_id=self.correlation_id,
            user_id=self.user_id,
            session_id=self.session_id,
            conversation_id=self.conversation_id,
            start_time=self.start_time,
            metadata=new_metadata
        )


def get_request_context() -> Optional[CorrelationContext]:
    """
    Get the current request context.
    
    Returns:
        Current request context or None if not set
    """
    return _request_context_var.get()


def set_request_context(context: CorrelationContext) -> None:
    """
    Set the request context.
    
    Args:
        context: Request context to set
    """
    _request_context_var.set(context)
    _correlation_id_var.set(context.correlation_id)


def clear_request_context() -> None:
    """Clear the request context."""
    _request_context_var.set(None)
    _correlation_id_var.set(None)


@contextmanager
def correlation_context(
    correlation_id: Optional[str] = None,
    user_id: Optional[str] = None,
    session_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    **metadata: Any
) -> Generator[CorrelationContext, None, None]:
    """
    Context manager for setting up request correlation context.
    
    This creates a new correlation context and ensures it's properly
    cleaned up when the context exits.
    
    Args:
        correlation_id: Correlation ID (auto-generated if not provided)
        user_id: User identifier
        session_id: Session identifier
        conversation_id: Conversation identifier
        **metadata: Additional metadata to include in context
        
    Yields:
        The correlation context object
        
    Example:
        with correlation_context(user_id="user-123") as ctx:
            logger.info("Processing request", correlation_id=ctx.correlation_id)
    """
    # Save previous context
    previous_context = _request_context_var.get()
    previous_correlation_id = _correlation_id_var.get()
    
    # Create new context
    context = CorrelationContext(
        correlation_id=correlation_id or generate_correlation_id(),
        user_id=user_id,
        session_id=session_id,
        conversation_id=conversation_id,
        metadata=metadata
    )
    
    # Set new context
    set_request_context(context)
    
    try:
        yield context
    finally:
        # Restore previous context
        if previous_context is not None:
            _request_context_var.set(previous_context)
            _correlation_id_var.set(previous_correlation_id)
        else:
            clear_request_context()


def get_log_context() -> Dict[str, Any]:
    """
    Get current logging context as dictionary.
    
    Returns:
        Dictionary with correlation context values for logging
    """
    context = get_request_context()
    if context is not None:
        return context.to_dict()
    
    correlation_id = get_correlation_id()
    if correlation_id is not None:
        return {"correlation_id": correlation_id}
    
    return {}
