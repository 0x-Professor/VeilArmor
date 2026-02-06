"""
VeilArmor - Conversation Manager

Manages multi-turn conversations with security context.
"""

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from src.llm.base import Message
from src.utils.logger import get_logger

logger = get_logger(__name__)


class TurnType(str, Enum):
    """Type of conversation turn."""
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


@dataclass
class SecurityContext:
    """Security context for a turn."""
    threat_score: float = 0.0
    threat_types: List[str] = field(default_factory=list)
    sanitized: bool = False
    blocked: bool = False
    classification_results: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationTurn:
    """Single turn in a conversation."""
    id: str
    type: TurnType
    content: str
    original_content: Optional[str] = None  # Before sanitization
    timestamp: float = field(default_factory=time.time)
    security_context: SecurityContext = field(default_factory=SecurityContext)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_message(self) -> Message:
        """Convert to LLM message."""
        return Message(
            role=self.type.value,
            content=self.content,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.type.value,
            "content": self.content,
            "original_content": self.original_content,
            "timestamp": self.timestamp,
            "security_context": {
                "threat_score": self.security_context.threat_score,
                "threat_types": self.security_context.threat_types,
                "sanitized": self.security_context.sanitized,
                "blocked": self.security_context.blocked,
            },
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConversationTurn":
        """Create from dictionary."""
        security_data = data.get("security_context", {})
        return cls(
            id=data["id"],
            type=TurnType(data["type"]),
            content=data["content"],
            original_content=data.get("original_content"),
            timestamp=data.get("timestamp", time.time()),
            security_context=SecurityContext(
                threat_score=security_data.get("threat_score", 0.0),
                threat_types=security_data.get("threat_types", []),
                sanitized=security_data.get("sanitized", False),
                blocked=security_data.get("blocked", False),
            ),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ConversationConfig:
    """Configuration for conversation management."""
    max_turns: int = 100
    max_tokens: int = 128000
    max_context_window: int = 20
    include_system_prompt: bool = True
    track_security_context: bool = True
    auto_summarize: bool = False
    summarize_threshold: int = 50


@dataclass
class Conversation:
    """Conversation container."""
    id: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    turns: List[ConversationTurn] = field(default_factory=list)
    system_prompt: Optional[str] = None
    config: ConversationConfig = field(default_factory=ConversationConfig)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def turn_count(self) -> int:
        """Get number of turns."""
        return len(self.turns)
    
    @property
    def user_turn_count(self) -> int:
        """Get number of user turns."""
        return len([t for t in self.turns if t.type == TurnType.USER])
    
    @property
    def last_turn(self) -> Optional[ConversationTurn]:
        """Get last turn."""
        return self.turns[-1] if self.turns else None
    
    @property
    def total_threat_score(self) -> float:
        """Get cumulative threat score."""
        if not self.turns:
            return 0.0
        return sum(t.security_context.threat_score for t in self.turns)
    
    @property
    def avg_threat_score(self) -> float:
        """Get average threat score."""
        if not self.turns:
            return 0.0
        return self.total_threat_score / len(self.turns)
    
    def add_turn(self, turn: ConversationTurn) -> None:
        """Add a turn to the conversation."""
        self.turns.append(turn)
        self.updated_at = time.time()
    
    def get_messages(
        self,
        include_system: bool = True,
        max_turns: Optional[int] = None,
    ) -> List[Message]:
        """
        Get messages for LLM.
        
        Args:
            include_system: Include system prompt
            max_turns: Maximum turns to include
            
        Returns:
            List of messages
        """
        messages = []
        
        if include_system and self.system_prompt:
            messages.append(Message(role="system", content=self.system_prompt))
        
        turns = self.turns
        if max_turns is not None:
            turns = turns[-max_turns:]
        
        for turn in turns:
            if not turn.security_context.blocked:
                messages.append(turn.to_message())
        
        return messages
    
    def get_context_window(
        self,
        window_size: Optional[int] = None,
    ) -> List[ConversationTurn]:
        """
        Get recent turns within context window.
        
        Args:
            window_size: Window size (uses config default if None)
            
        Returns:
            List of recent turns
        """
        size = window_size or self.config.max_context_window
        return self.turns[-size:] if self.turns else []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "turns": [t.to_dict() for t in self.turns],
            "system_prompt": self.system_prompt,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Conversation":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            created_at=data.get("created_at", time.time()),
            updated_at=data.get("updated_at", time.time()),
            turns=[ConversationTurn.from_dict(t) for t in data.get("turns", [])],
            system_prompt=data.get("system_prompt"),
            metadata=data.get("metadata", {}),
        )


class ConversationManager:
    """
    Manages conversations with security tracking.
    
    Features:
    - Multi-turn conversation management
    - Security context tracking
    - Sliding window context
    - Conversation persistence
    """
    
    def __init__(
        self,
        storage: Optional[Any] = None,  # ConversationStorage
        default_config: Optional[ConversationConfig] = None,
        default_system_prompt: Optional[str] = None,
    ):
        """
        Initialize conversation manager.
        
        Args:
            storage: Conversation storage backend
            default_config: Default conversation configuration
            default_system_prompt: Default system prompt
        """
        self.storage = storage
        self.default_config = default_config or ConversationConfig()
        self.default_system_prompt = default_system_prompt
        
        # In-memory conversations (for storage-less mode)
        self._conversations: Dict[str, Conversation] = {}
        
        # Metrics
        self._total_conversations = 0
        self._total_turns = 0
        
        logger.info("Conversation manager initialized")
    
    def create_conversation(
        self,
        conversation_id: Optional[str] = None,
        system_prompt: Optional[str] = None,
        config: Optional[ConversationConfig] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Conversation:
        """
        Create a new conversation.
        
        Args:
            conversation_id: Optional ID (generated if not provided)
            system_prompt: System prompt
            config: Conversation configuration
            metadata: Additional metadata
            
        Returns:
            New conversation
        """
        conv_id = conversation_id or str(uuid.uuid4())
        
        conversation = Conversation(
            id=conv_id,
            system_prompt=system_prompt or self.default_system_prompt,
            config=config or self.default_config,
            metadata=metadata or {},
        )
        
        self._conversations[conv_id] = conversation
        self._total_conversations += 1
        
        logger.debug("Conversation created", conversation_id=conv_id)
        
        return conversation
    
    async def get_conversation(
        self,
        conversation_id: str,
    ) -> Optional[Conversation]:
        """
        Get a conversation by ID.
        
        Args:
            conversation_id: Conversation ID
            
        Returns:
            Conversation or None
        """
        # Check memory first
        if conversation_id in self._conversations:
            return self._conversations[conversation_id]
        
        # Check storage
        if self.storage:
            conversation = await self.storage.get(conversation_id)
            if conversation:
                self._conversations[conversation_id] = conversation
                return conversation
        
        return None
    
    async def save_conversation(
        self,
        conversation: Conversation,
    ) -> bool:
        """
        Save a conversation.
        
        Args:
            conversation: Conversation to save
            
        Returns:
            True if saved successfully
        """
        self._conversations[conversation.id] = conversation
        
        if self.storage:
            return await self.storage.save(conversation)
        
        return True
    
    async def delete_conversation(
        self,
        conversation_id: str,
    ) -> bool:
        """
        Delete a conversation.
        
        Args:
            conversation_id: Conversation ID
            
        Returns:
            True if deleted
        """
        deleted = self._conversations.pop(conversation_id, None) is not None
        
        if self.storage:
            storage_deleted = await self.storage.delete(conversation_id)
            deleted = deleted or storage_deleted
        
        return deleted
    
    def add_user_turn(
        self,
        conversation: Conversation,
        content: str,
        original_content: Optional[str] = None,
        security_context: Optional[SecurityContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ConversationTurn:
        """
        Add a user turn to conversation.
        
        Args:
            conversation: Conversation
            content: Turn content (potentially sanitized)
            original_content: Original content before sanitization
            security_context: Security context
            metadata: Additional metadata
            
        Returns:
            Created turn
        """
        turn = ConversationTurn(
            id=str(uuid.uuid4()),
            type=TurnType.USER,
            content=content,
            original_content=original_content,
            security_context=security_context or SecurityContext(),
            metadata=metadata or {},
        )
        
        conversation.add_turn(turn)
        self._total_turns += 1
        
        return turn
    
    def add_assistant_turn(
        self,
        conversation: Conversation,
        content: str,
        original_content: Optional[str] = None,
        security_context: Optional[SecurityContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ConversationTurn:
        """
        Add an assistant turn to conversation.
        
        Args:
            conversation: Conversation
            content: Turn content (potentially sanitized)
            original_content: Original content before sanitization
            security_context: Security context
            metadata: Additional metadata
            
        Returns:
            Created turn
        """
        turn = ConversationTurn(
            id=str(uuid.uuid4()),
            type=TurnType.ASSISTANT,
            content=content,
            original_content=original_content,
            security_context=security_context or SecurityContext(),
            metadata=metadata or {},
        )
        
        conversation.add_turn(turn)
        self._total_turns += 1
        
        return turn
    
    def get_messages_for_llm(
        self,
        conversation: Conversation,
        include_system: bool = True,
        max_turns: Optional[int] = None,
    ) -> List[Message]:
        """
        Get messages formatted for LLM.
        
        Args:
            conversation: Conversation
            include_system: Include system prompt
            max_turns: Maximum turns to include
            
        Returns:
            List of messages
        """
        return conversation.get_messages(
            include_system=include_system,
            max_turns=max_turns or conversation.config.max_context_window,
        )
    
    def get_security_summary(
        self,
        conversation: Conversation,
    ) -> Dict[str, Any]:
        """
        Get security summary for conversation.
        
        Args:
            conversation: Conversation
            
        Returns:
            Security summary
        """
        threat_scores = [
            t.security_context.threat_score for t in conversation.turns
        ]
        
        all_threats = []
        blocked_count = 0
        sanitized_count = 0
        
        for turn in conversation.turns:
            all_threats.extend(turn.security_context.threat_types)
            if turn.security_context.blocked:
                blocked_count += 1
            if turn.security_context.sanitized:
                sanitized_count += 1
        
        return {
            "total_turns": len(conversation.turns),
            "avg_threat_score": sum(threat_scores) / len(threat_scores) if threat_scores else 0.0,
            "max_threat_score": max(threat_scores) if threat_scores else 0.0,
            "unique_threats": list(set(all_threats)),
            "blocked_turns": blocked_count,
            "sanitized_turns": sanitized_count,
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get manager metrics."""
        return {
            "total_conversations": self._total_conversations,
            "active_conversations": len(self._conversations),
            "total_turns": self._total_turns,
        }
    
    async def list_conversations(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Conversation]:
        """
        List conversations.
        
        Args:
            limit: Maximum results
            offset: Offset for pagination
            
        Returns:
            List of conversations
        """
        if self.storage:
            return await self.storage.list(limit=limit, offset=offset)
        
        conversations = list(self._conversations.values())
        conversations.sort(key=lambda c: c.updated_at, reverse=True)
        
        return conversations[offset:offset + limit]
