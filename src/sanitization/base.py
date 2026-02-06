"""
VeilArmor v2.0 - Sanitization Base

Base classes for sanitization with strategy pattern support.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SanitizerType(str, Enum):
    """Types of sanitizers."""
    INPUT = "input"
    OUTPUT = "output"


class SanitizationStrategy(str, Enum):
    """Available sanitization strategies."""
    REDACT = "redact"           # Replace with [REDACTED]
    MASK = "mask"               # Replace with asterisks
    REMOVE = "remove"           # Remove entirely
    REPLACE = "replace"         # Replace with safe alternative
    NORMALIZE = "normalize"     # Normalize to standard form
    ESCAPE = "escape"           # HTML/special character escape
    FILTER = "filter"           # Filter out specific patterns
    TRANSFORM = "transform"     # Transform to safer version
    CUSTOM = "custom"           # Custom strategy


@dataclass
class SanitizationResult:
    """Result from sanitization operation."""
    original_text: str
    sanitized_text: str
    was_modified: bool
    changes: List[Dict[str, Any]] = field(default_factory=list)
    strategies_applied: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def change_count(self) -> int:
        """Number of changes made."""
        return len(self.changes)
    
    @property
    def has_changes(self) -> bool:
        """Check if any changes were made."""
        return self.was_modified
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "was_modified": self.was_modified,
            "change_count": self.change_count,
            "strategies_applied": self.strategies_applied,
            "changes": self.changes,
            "metadata": self.metadata,
        }


class BaseSanitizationStrategy(ABC):
    """Base class for sanitization strategies."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Strategy name."""
        pass
    
    @property
    @abstractmethod
    def strategy_type(self) -> SanitizationStrategy:
        """Strategy type."""
        pass
    
    @abstractmethod
    def apply(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """
        Apply sanitization strategy.
        
        Args:
            text: Text to sanitize
            context: Optional context with detection results
            
        Returns:
            Tuple of (sanitized_text, changes_list)
        """
        pass
    
    @property
    def description(self) -> str:
        """Strategy description."""
        return f"{self.name} sanitization strategy"


class BaseSanitizer(ABC):
    """Base class for sanitizers."""
    
    def __init__(self):
        """Initialize sanitizer."""
        self._strategies: List[BaseSanitizationStrategy] = []
        self._enabled = True
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Sanitizer name."""
        pass
    
    @property
    @abstractmethod
    def sanitizer_type(self) -> SanitizerType:
        """Sanitizer type (input/output)."""
        pass
    
    @property
    def description(self) -> str:
        """Sanitizer description."""
        return f"{self.name} sanitizer"
    
    @property
    def enabled(self) -> bool:
        """Check if sanitizer is enabled."""
        return self._enabled
    
    def enable(self) -> None:
        """Enable sanitizer."""
        self._enabled = True
    
    def disable(self) -> None:
        """Disable sanitizer."""
        self._enabled = False
    
    def add_strategy(self, strategy: BaseSanitizationStrategy) -> None:
        """Add a sanitization strategy."""
        self._strategies.append(strategy)
    
    def remove_strategy(self, name: str) -> bool:
        """Remove a strategy by name."""
        for i, strategy in enumerate(self._strategies):
            if strategy.name == name:
                self._strategies.pop(i)
                return True
        return False
    
    def get_strategies(self) -> List[BaseSanitizationStrategy]:
        """Get all strategies."""
        return self._strategies.copy()
    
    @abstractmethod
    def sanitize(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SanitizationResult:
        """
        Sanitize text.
        
        Args:
            text: Text to sanitize
            context: Optional context with detection results
            
        Returns:
            SanitizationResult with sanitized text and changes
        """
        pass
    
    def _apply_strategies(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """
        Apply all strategies to text.
        
        Returns:
            Tuple of (sanitized_text, all_changes, applied_strategies)
        """
        all_changes = []
        applied_strategies = []
        
        for strategy in self._strategies:
            sanitized, changes = strategy.apply(text, context)
            if sanitized != text:
                text = sanitized
                applied_strategies.append(strategy.name)
            if changes:
                all_changes.extend(changes)
        
        return text, all_changes, applied_strategies


# Registry for sanitization strategies
_strategy_registry: Dict[str, type] = {}


def register_strategy(name: str):
    """Decorator to register a sanitization strategy."""
    def decorator(cls):
        _strategy_registry[name] = cls
        return cls
    return decorator


def get_strategy(name: str) -> Optional[type]:
    """Get a registered strategy by name."""
    return _strategy_registry.get(name)


def get_all_strategies() -> Dict[str, type]:
    """Get all registered strategies."""
    return _strategy_registry.copy()
