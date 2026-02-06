"""
VeilArmor - Base LLM Interface

Abstract base classes for LLM providers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    HUGGINGFACE = "huggingface"
    AZURE = "azure"
    COHERE = "cohere"
    OLLAMA = "ollama"
    CUSTOM = "custom"
    DUMMY = "dummy"


@dataclass
class Message:
    """Chat message."""
    role: str  # system, user, assistant
    content: str
    name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API calls."""
        result = {"role": self.role, "content": self.content}
        if self.name:
            result["name"] = self.name
        return result


@dataclass
class LLMRequest:
    """LLM request configuration."""
    messages: List[Message]
    model: Optional[str] = None
    temperature: float = 0.7
    max_tokens: Optional[int] = None
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    stop: Optional[List[str]] = None
    stream: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dictionary."""
        result = {
            "messages": [m.to_dict() for m in self.messages],
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        
        if self.model:
            result["model"] = self.model
        if self.max_tokens is not None:
            result["max_tokens"] = self.max_tokens
        if self.frequency_penalty is not None:
            result["frequency_penalty"] = self.frequency_penalty
        if self.presence_penalty is not None:
            result["presence_penalty"] = self.presence_penalty
        if self.stop:
            result["stop"] = self.stop
        if self.stream:
            result["stream"] = self.stream
        
        return result


@dataclass
class LLMResponse:
    """LLM response."""
    content: str
    model: str
    provider: str
    finish_reason: str = "stop"
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def total_cost(self) -> float:
        """Calculate estimated cost based on tokens."""
        # Cost estimation - can be customized per model
        return self.metadata.get("estimated_cost", 0.0)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider,
            "finish_reason": self.finish_reason,
            "usage": {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
            },
            "latency_ms": self.latency_ms,
            "metadata": self.metadata,
        }


@dataclass
class StreamChunk:
    """Streaming response chunk."""
    content: str
    is_final: bool = False
    finish_reason: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseLLM(ABC):
    """Abstract base class for LLM providers."""
    
    def __init__(
        self,
        model: str,
        provider: LLMProvider,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
        max_retries: int = 3,
    ):
        """
        Initialize LLM provider.
        
        Args:
            model: Model identifier
            provider: Provider type
            api_key: API key for authentication
            base_url: Base URL for API requests
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self.model = model
        self.provider = provider
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self._available = True
    
    @abstractmethod
    async def generate(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        """
        Generate response from LLM.
        
        Args:
            request: LLM request
            
        Returns:
            LLM response
        """
        pass
    
    @abstractmethod
    async def generate_stream(
        self,
        request: LLMRequest,
    ) -> AsyncIterator[StreamChunk]:
        """
        Generate streaming response from LLM.
        
        Args:
            request: LLM request
            
        Yields:
            Stream chunks
        """
        pass
    
    async def chat(
        self,
        messages: List[Message],
        **kwargs,
    ) -> LLMResponse:
        """
        Convenience method for chat completions.
        
        Args:
            messages: List of messages
            **kwargs: Additional request parameters
            
        Returns:
            LLM response
        """
        request = LLMRequest(messages=messages, **kwargs)
        return await self.generate(request)
    
    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """
        Convenience method for simple completions.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            **kwargs: Additional request parameters
            
        Returns:
            LLM response
        """
        messages = []
        
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        
        messages.append(Message(role="user", content=prompt))
        
        return await self.chat(messages, **kwargs)
    
    def is_available(self) -> bool:
        """Check if provider is available."""
        return self._available
    
    def set_available(self, available: bool) -> None:
        """Set availability status."""
        self._available = available
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        return {
            "model": self.model,
            "provider": self.provider.value,
            "available": self._available,
        }
    
    def __repr__(self) -> str:
        """String representation."""
        return f"{self.__class__.__name__}(model={self.model}, provider={self.provider.value})"
