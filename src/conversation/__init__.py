"""
VeilArmor v2.0 - Conversation Module

Multi-turn conversation management with context handling.
"""

from src.conversation.manager import (
    ConversationManager,
    Conversation,
    ConversationTurn,
    ConversationConfig,
)
from src.conversation.context import (
    ContextManager,
    SlidingWindowContext,
    SummaryContext,
)
from src.conversation.storage import (
    ConversationStorage,
    MemoryConversationStorage,
    RedisConversationStorage,
)


__all__ = [
    # Manager
    "ConversationManager",
    "Conversation",
    "ConversationTurn",
    "ConversationConfig",
    # Context
    "ContextManager",
    "SlidingWindowContext",
    "SummaryContext",
    # Storage
    "ConversationStorage",
    "MemoryConversationStorage",
    "RedisConversationStorage",
]
