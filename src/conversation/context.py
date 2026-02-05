"""
VeilArmor v2.0 - Context Management

Context strategies for conversation management.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.llm.base import Message
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ContextConfig:
    """Context configuration."""
    max_tokens: int = 128000
    max_messages: int = 100
    preserve_system: bool = True
    preserve_first_user: bool = True
    token_estimator: str = "simple"  # simple, tiktoken


class ContextManager(ABC):
    """Abstract base class for context management."""
    
    def __init__(self, config: Optional[ContextConfig] = None):
        """Initialize context manager."""
        self.config = config or ContextConfig()
    
    @abstractmethod
    def get_context(
        self,
        messages: List[Message],
        max_tokens: Optional[int] = None,
    ) -> List[Message]:
        """
        Get context messages within token limit.
        
        Args:
            messages: All messages
            max_tokens: Maximum tokens
            
        Returns:
            Context messages
        """
        pass
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text.
        
        Args:
            text: Input text
            
        Returns:
            Estimated token count
        """
        if self.config.token_estimator == "simple":
            # Simple estimation: ~4 chars per token
            return len(text) // 4
        
        # Could add tiktoken support here
        return len(text) // 4
    
    def estimate_message_tokens(self, message: Message) -> int:
        """
        Estimate token count for message.
        
        Args:
            message: Message
            
        Returns:
            Estimated token count
        """
        # Account for message overhead
        overhead = 4  # role, content wrappers
        return self.estimate_tokens(message.content) + overhead


class SlidingWindowContext(ContextManager):
    """
    Sliding window context management.
    
    Keeps most recent messages within token limit.
    """
    
    def __init__(
        self,
        window_size: int = 20,
        config: Optional[ContextConfig] = None,
    ):
        """
        Initialize sliding window context.
        
        Args:
            window_size: Maximum messages in window
            config: Context configuration
        """
        super().__init__(config)
        self.window_size = window_size
    
    def get_context(
        self,
        messages: List[Message],
        max_tokens: Optional[int] = None,
    ) -> List[Message]:
        """
        Get context using sliding window.
        
        Args:
            messages: All messages
            max_tokens: Maximum tokens
            
        Returns:
            Context messages
        """
        if not messages:
            return []
        
        max_tokens = max_tokens or self.config.max_tokens
        
        result = []
        total_tokens = 0
        
        # Separate system message if present
        system_message = None
        other_messages = []
        
        for msg in messages:
            if msg.role == "system" and self.config.preserve_system:
                system_message = msg
            else:
                other_messages.append(msg)
        
        # Add system message first if present
        if system_message:
            system_tokens = self.estimate_message_tokens(system_message)
            result.append(system_message)
            total_tokens += system_tokens
        
        # Take most recent messages from window
        window = other_messages[-self.window_size:]
        
        # Add messages that fit within token limit
        for msg in window:
            msg_tokens = self.estimate_message_tokens(msg)
            
            if total_tokens + msg_tokens <= max_tokens:
                result.append(msg)
                total_tokens += msg_tokens
            else:
                break
        
        # Ensure at least one user message if available
        user_messages = [m for m in result if m.role == "user"]
        if not user_messages and other_messages:
            last_user = None
            for msg in reversed(other_messages):
                if msg.role == "user":
                    last_user = msg
                    break
            
            if last_user and last_user not in result:
                result.append(last_user)
        
        return result


class SummaryContext(ContextManager):
    """
    Summary-based context management.
    
    Maintains a rolling summary of older messages.
    """
    
    def __init__(
        self,
        recent_messages: int = 10,
        summary_interval: int = 20,
        config: Optional[ContextConfig] = None,
    ):
        """
        Initialize summary context.
        
        Args:
            recent_messages: Number of recent messages to keep
            summary_interval: Interval for summary updates
            config: Context configuration
        """
        super().__init__(config)
        self.recent_messages = recent_messages
        self.summary_interval = summary_interval
        self._summaries: Dict[str, str] = {}  # conversation_id -> summary
    
    def get_context(
        self,
        messages: List[Message],
        max_tokens: Optional[int] = None,
        conversation_id: Optional[str] = None,
    ) -> List[Message]:
        """
        Get context with summary.
        
        Args:
            messages: All messages
            max_tokens: Maximum tokens
            conversation_id: Conversation ID for summary lookup
            
        Returns:
            Context messages with summary
        """
        if not messages:
            return []
        
        max_tokens = max_tokens or self.config.max_tokens
        
        result = []
        total_tokens = 0
        
        # Separate system message
        system_message = None
        other_messages = []
        
        for msg in messages:
            if msg.role == "system" and self.config.preserve_system:
                system_message = msg
            else:
                other_messages.append(msg)
        
        # Add system message
        if system_message:
            result.append(system_message)
            total_tokens += self.estimate_message_tokens(system_message)
        
        # Add summary if available
        if conversation_id and conversation_id in self._summaries:
            summary = self._summaries[conversation_id]
            summary_msg = Message(
                role="system",
                content=f"[Previous conversation summary: {summary}]",
            )
            result.append(summary_msg)
            total_tokens += self.estimate_message_tokens(summary_msg)
        
        # Add recent messages
        recent = other_messages[-self.recent_messages:]
        
        for msg in recent:
            msg_tokens = self.estimate_message_tokens(msg)
            
            if total_tokens + msg_tokens <= max_tokens:
                result.append(msg)
                total_tokens += msg_tokens
        
        return result
    
    def update_summary(
        self,
        conversation_id: str,
        summary: str,
    ) -> None:
        """
        Update conversation summary.
        
        Args:
            conversation_id: Conversation ID
            summary: New summary
        """
        self._summaries[conversation_id] = summary
    
    def get_summary(
        self,
        conversation_id: str,
    ) -> Optional[str]:
        """
        Get conversation summary.
        
        Args:
            conversation_id: Conversation ID
            
        Returns:
            Summary or None
        """
        return self._summaries.get(conversation_id)
    
    def clear_summary(
        self,
        conversation_id: str,
    ) -> bool:
        """
        Clear conversation summary.
        
        Args:
            conversation_id: Conversation ID
            
        Returns:
            True if cleared
        """
        return self._summaries.pop(conversation_id, None) is not None


class TokenBudgetContext(ContextManager):
    """
    Token budget-based context management.
    
    Allocates token budgets to different message types.
    """
    
    def __init__(
        self,
        system_budget: float = 0.1,  # 10% for system
        context_budget: float = 0.4,  # 40% for context
        recent_budget: float = 0.5,  # 50% for recent
        config: Optional[ContextConfig] = None,
    ):
        """
        Initialize token budget context.
        
        Args:
            system_budget: Fraction for system messages
            context_budget: Fraction for context messages
            recent_budget: Fraction for recent messages
            config: Context configuration
        """
        super().__init__(config)
        self.system_budget = system_budget
        self.context_budget = context_budget
        self.recent_budget = recent_budget
    
    def get_context(
        self,
        messages: List[Message],
        max_tokens: Optional[int] = None,
    ) -> List[Message]:
        """
        Get context using token budgets.
        
        Args:
            messages: All messages
            max_tokens: Maximum tokens
            
        Returns:
            Context messages
        """
        if not messages:
            return []
        
        max_tokens = max_tokens or self.config.max_tokens
        
        # Calculate budgets
        system_tokens = int(max_tokens * self.system_budget)
        context_tokens = int(max_tokens * self.context_budget)
        recent_tokens = int(max_tokens * self.recent_budget)
        
        result = []
        
        # Separate message types
        system_messages = []
        other_messages = []
        
        for msg in messages:
            if msg.role == "system":
                system_messages.append(msg)
            else:
                other_messages.append(msg)
        
        # Add system messages within budget
        system_used = 0
        for msg in system_messages:
            msg_tokens = self.estimate_message_tokens(msg)
            if system_used + msg_tokens <= system_tokens:
                result.append(msg)
                system_used += msg_tokens
        
        # Split other messages into context and recent
        if len(other_messages) > 10:
            context_messages = other_messages[:-10]
            recent_messages = other_messages[-10:]
        else:
            context_messages = []
            recent_messages = other_messages
        
        # Add context messages within budget
        context_used = 0
        for msg in context_messages:
            msg_tokens = self.estimate_message_tokens(msg)
            if context_used + msg_tokens <= context_tokens:
                result.append(msg)
                context_used += msg_tokens
        
        # Add recent messages within budget
        recent_used = 0
        for msg in recent_messages:
            msg_tokens = self.estimate_message_tokens(msg)
            if recent_used + msg_tokens <= recent_tokens:
                result.append(msg)
                recent_used += msg_tokens
        
        return result


class CompactContext(ContextManager):
    """
    Compact context that removes less important messages.
    
    Prioritizes messages based on importance scoring.
    """
    
    def __init__(
        self,
        importance_scorer: Optional[callable] = None,
        config: Optional[ContextConfig] = None,
    ):
        """
        Initialize compact context.
        
        Args:
            importance_scorer: Function to score message importance
            config: Context configuration
        """
        super().__init__(config)
        self.importance_scorer = importance_scorer or self._default_importance
    
    def _default_importance(self, message: Message, index: int, total: int) -> float:
        """
        Default importance scoring.
        
        Args:
            message: Message
            index: Message index
            total: Total messages
            
        Returns:
            Importance score (0-1)
        """
        score = 0.0
        
        # System messages are important
        if message.role == "system":
            score += 0.5
        
        # User messages slightly more important than assistant
        if message.role == "user":
            score += 0.3
        else:
            score += 0.2
        
        # Recent messages more important
        recency = (index + 1) / total
        score += recency * 0.5
        
        return min(1.0, score)
    
    def get_context(
        self,
        messages: List[Message],
        max_tokens: Optional[int] = None,
    ) -> List[Message]:
        """
        Get context using importance scoring.
        
        Args:
            messages: All messages
            max_tokens: Maximum tokens
            
        Returns:
            Context messages
        """
        if not messages:
            return []
        
        max_tokens = max_tokens or self.config.max_tokens
        
        # Score all messages
        scored = [
            (msg, self.importance_scorer(msg, i, len(messages)), i)
            for i, msg in enumerate(messages)
        ]
        
        # Sort by importance (descending), then by index (ascending) for ties
        scored.sort(key=lambda x: (-x[1], x[2]))
        
        # Select messages within token limit
        result = []
        total_tokens = 0
        selected_indices = []
        
        for msg, score, idx in scored:
            msg_tokens = self.estimate_message_tokens(msg)
            
            if total_tokens + msg_tokens <= max_tokens:
                selected_indices.append(idx)
                total_tokens += msg_tokens
        
        # Sort by original order
        selected_indices.sort()
        
        for idx in selected_indices:
            result.append(messages[idx])
        
        return result
