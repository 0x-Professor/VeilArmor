"""
VeilArmor v2.0 - Conversation Storage

Storage backends for conversation persistence.
"""

import asyncio
import json
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from src.conversation.manager import Conversation
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ConversationStorage(ABC):
    """Abstract base class for conversation storage."""
    
    @abstractmethod
    async def save(self, conversation: Conversation) -> bool:
        """Save a conversation."""
        pass
    
    @abstractmethod
    async def get(self, conversation_id: str) -> Optional[Conversation]:
        """Get a conversation by ID."""
        pass
    
    @abstractmethod
    async def delete(self, conversation_id: str) -> bool:
        """Delete a conversation."""
        pass
    
    @abstractmethod
    async def list(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Conversation]:
        """List conversations."""
        pass
    
    @abstractmethod
    async def exists(self, conversation_id: str) -> bool:
        """Check if conversation exists."""
        pass


class MemoryConversationStorage(ConversationStorage):
    """
    In-memory conversation storage.
    
    Suitable for development and testing.
    """
    
    def __init__(
        self,
        max_conversations: int = 10000,
        auto_cleanup: bool = True,
        cleanup_age_hours: int = 24,
    ):
        """
        Initialize memory storage.
        
        Args:
            max_conversations: Maximum conversations to store
            auto_cleanup: Enable automatic cleanup
            cleanup_age_hours: Age threshold for cleanup
        """
        self.max_conversations = max_conversations
        self.auto_cleanup = auto_cleanup
        self.cleanup_age_hours = cleanup_age_hours
        
        self._conversations: Dict[str, Conversation] = {}
        self._lock = asyncio.Lock()
        
        logger.info(
            "Memory conversation storage initialized",
            max_conversations=max_conversations,
        )
    
    async def save(self, conversation: Conversation) -> bool:
        """Save a conversation."""
        async with self._lock:
            # Check capacity
            if (
                len(self._conversations) >= self.max_conversations
                and conversation.id not in self._conversations
            ):
                if self.auto_cleanup:
                    await self._cleanup()
                
                # If still at capacity, evict oldest
                if len(self._conversations) >= self.max_conversations:
                    await self._evict_oldest()
            
            self._conversations[conversation.id] = conversation
            
            return True
    
    async def get(self, conversation_id: str) -> Optional[Conversation]:
        """Get a conversation by ID."""
        async with self._lock:
            return self._conversations.get(conversation_id)
    
    async def delete(self, conversation_id: str) -> bool:
        """Delete a conversation."""
        async with self._lock:
            if conversation_id in self._conversations:
                del self._conversations[conversation_id]
                return True
            return False
    
    async def list(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Conversation]:
        """List conversations."""
        async with self._lock:
            conversations = list(self._conversations.values())
            conversations.sort(key=lambda c: c.updated_at, reverse=True)
            
            return conversations[offset:offset + limit]
    
    async def exists(self, conversation_id: str) -> bool:
        """Check if conversation exists."""
        async with self._lock:
            return conversation_id in self._conversations
    
    async def _cleanup(self) -> int:
        """Clean up old conversations."""
        cutoff = time.time() - (self.cleanup_age_hours * 3600)
        
        to_remove = [
            conv_id for conv_id, conv in self._conversations.items()
            if conv.updated_at < cutoff
        ]
        
        for conv_id in to_remove:
            del self._conversations[conv_id]
        
        logger.debug(
            "Memory storage cleanup completed",
            removed=len(to_remove),
        )
        
        return len(to_remove)
    
    async def _evict_oldest(self) -> None:
        """Evict oldest conversation."""
        if not self._conversations:
            return
        
        oldest_id = min(
            self._conversations.keys(),
            key=lambda k: self._conversations[k].updated_at,
        )
        
        del self._conversations[oldest_id]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        return {
            "total_conversations": len(self._conversations),
            "max_conversations": self.max_conversations,
            "auto_cleanup": self.auto_cleanup,
        }


class RedisConversationStorage(ConversationStorage):
    """
    Redis-based conversation storage.
    
    Features:
    - Persistent storage
    - TTL support
    - Scalable across instances
    """
    
    def __init__(
        self,
        url: str = "redis://localhost:6379",
        db: int = 0,
        prefix: str = "veilarmor:conv:",
        default_ttl: int = 86400 * 7,  # 7 days
    ):
        """
        Initialize Redis storage.
        
        Args:
            url: Redis URL
            db: Database number
            prefix: Key prefix
            default_ttl: Default TTL in seconds
        """
        self.url = url
        self.db = db
        self.prefix = prefix
        self.default_ttl = default_ttl
        
        self._redis = None
        self._connected = False
        
        logger.info(
            "Redis conversation storage initialized",
            prefix=prefix,
        )
    
    async def _ensure_connected(self) -> None:
        """Ensure Redis connection."""
        if self._connected and self._redis:
            return
        
        try:
            import redis.asyncio as redis
            
            self._redis = redis.from_url(
                self.url,
                db=self.db,
                decode_responses=True,
            )
            
            await self._redis.ping()
            self._connected = True
            
            logger.info("Redis conversation storage connected")
            
        except ImportError:
            logger.error("redis package not installed")
            raise ImportError("redis package required")
        except Exception as e:
            logger.error("Failed to connect to Redis", error=str(e))
            raise
    
    def _make_key(self, conversation_id: str) -> str:
        """Create prefixed key."""
        return f"{self.prefix}{conversation_id}"
    
    async def save(self, conversation: Conversation) -> bool:
        """Save a conversation."""
        await self._ensure_connected()
        
        try:
            key = self._make_key(conversation.id)
            data = json.dumps(conversation.to_dict())
            
            await self._redis.setex(key, self.default_ttl, data)
            
            # Update index
            await self._redis.zadd(
                f"{self.prefix}index",
                {conversation.id: conversation.updated_at},
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to save conversation",
                conversation_id=conversation.id,
                error=str(e),
            )
            return False
    
    async def get(self, conversation_id: str) -> Optional[Conversation]:
        """Get a conversation by ID."""
        await self._ensure_connected()
        
        try:
            key = self._make_key(conversation_id)
            data = await self._redis.get(key)
            
            if data is None:
                return None
            
            return Conversation.from_dict(json.loads(data))
            
        except Exception as e:
            logger.error(
                "Failed to get conversation",
                conversation_id=conversation_id,
                error=str(e),
            )
            return None
    
    async def delete(self, conversation_id: str) -> bool:
        """Delete a conversation."""
        await self._ensure_connected()
        
        try:
            key = self._make_key(conversation_id)
            result = await self._redis.delete(key)
            
            # Remove from index
            await self._redis.zrem(f"{self.prefix}index", conversation_id)
            
            return result > 0
            
        except Exception as e:
            logger.error(
                "Failed to delete conversation",
                conversation_id=conversation_id,
                error=str(e),
            )
            return False
    
    async def list(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Conversation]:
        """List conversations."""
        await self._ensure_connected()
        
        try:
            # Get IDs from index (sorted by updated_at descending)
            ids = await self._redis.zrevrange(
                f"{self.prefix}index",
                offset,
                offset + limit - 1,
            )
            
            if not ids:
                return []
            
            # Get all conversations
            keys = [self._make_key(conv_id) for conv_id in ids]
            data = await self._redis.mget(keys)
            
            conversations = []
            for item in data:
                if item:
                    conversations.append(
                        Conversation.from_dict(json.loads(item))
                    )
            
            return conversations
            
        except Exception as e:
            logger.error("Failed to list conversations", error=str(e))
            return []
    
    async def exists(self, conversation_id: str) -> bool:
        """Check if conversation exists."""
        await self._ensure_connected()
        
        try:
            key = self._make_key(conversation_id)
            return await self._redis.exists(key) > 0
            
        except Exception as e:
            logger.error(
                "Failed to check conversation",
                conversation_id=conversation_id,
                error=str(e),
            )
            return False
    
    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._connected = False


class FileConversationStorage(ConversationStorage):
    """
    File-based conversation storage.
    
    Stores each conversation as a JSON file.
    """
    
    def __init__(
        self,
        base_path: str = "./conversations",
        create_dirs: bool = True,
    ):
        """
        Initialize file storage.
        
        Args:
            base_path: Base directory path
            create_dirs: Create directories if needed
        """
        import os
        
        self.base_path = base_path
        
        if create_dirs and not os.path.exists(base_path):
            os.makedirs(base_path)
        
        logger.info(
            "File conversation storage initialized",
            path=base_path,
        )
    
    def _get_path(self, conversation_id: str) -> str:
        """Get file path for conversation."""
        import os
        return os.path.join(self.base_path, f"{conversation_id}.json")
    
    async def save(self, conversation: Conversation) -> bool:
        """Save a conversation."""
        import aiofiles
        
        try:
            path = self._get_path(conversation.id)
            data = json.dumps(conversation.to_dict(), indent=2)
            
            async with aiofiles.open(path, 'w') as f:
                await f.write(data)
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to save conversation",
                conversation_id=conversation.id,
                error=str(e),
            )
            return False
    
    async def get(self, conversation_id: str) -> Optional[Conversation]:
        """Get a conversation by ID."""
        import aiofiles
        import os
        
        try:
            path = self._get_path(conversation_id)
            
            if not os.path.exists(path):
                return None
            
            async with aiofiles.open(path, 'r') as f:
                data = await f.read()
            
            return Conversation.from_dict(json.loads(data))
            
        except Exception as e:
            logger.error(
                "Failed to get conversation",
                conversation_id=conversation_id,
                error=str(e),
            )
            return None
    
    async def delete(self, conversation_id: str) -> bool:
        """Delete a conversation."""
        import os
        
        try:
            path = self._get_path(conversation_id)
            
            if os.path.exists(path):
                os.remove(path)
                return True
            
            return False
            
        except Exception as e:
            logger.error(
                "Failed to delete conversation",
                conversation_id=conversation_id,
                error=str(e),
            )
            return False
    
    async def list(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Conversation]:
        """List conversations."""
        import os
        
        try:
            files = []
            
            for filename in os.listdir(self.base_path):
                if filename.endswith('.json'):
                    path = os.path.join(self.base_path, filename)
                    mtime = os.path.getmtime(path)
                    files.append((filename[:-5], mtime))  # Remove .json
            
            # Sort by modification time (newest first)
            files.sort(key=lambda x: x[1], reverse=True)
            
            # Apply pagination
            files = files[offset:offset + limit]
            
            # Load conversations
            conversations = []
            for conv_id, _ in files:
                conv = await self.get(conv_id)
                if conv:
                    conversations.append(conv)
            
            return conversations
            
        except Exception as e:
            logger.error("Failed to list conversations", error=str(e))
            return []
    
    async def exists(self, conversation_id: str) -> bool:
        """Check if conversation exists."""
        import os
        return os.path.exists(self._get_path(conversation_id))
