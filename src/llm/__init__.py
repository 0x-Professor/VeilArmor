"""
VeilArmor - LLM Module

LLM provider abstraction with multi-provider support via LiteLLM.
"""

from src.llm.base import (
    BaseLLM,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    Message,
    StreamChunk,
)
from src.llm.providers import (
    LiteLLMProvider,
    OpenAIProvider,
    AnthropicProvider,
    GoogleProvider,
    AzureOpenAIProvider,
    OllamaProvider,
)
from src.llm.dummy_llm import (
    DummyLLM,
    EchoDummyLLM,
    TemplatedDummyLLM,
    StatefulDummyLLM,
)
from src.llm.gateway import (
    LLMGateway,
    LoadBalanceStrategy,
    ProviderConfig,
    get_llm_gateway,
)


__all__ = [
    # Base classes
    "BaseLLM",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "Message",
    "StreamChunk",
    # Providers
    "LiteLLMProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "GoogleProvider",
    "AzureOpenAIProvider",
    "OllamaProvider",
    # Dummy providers
    "DummyLLM",
    "EchoDummyLLM",
    "TemplatedDummyLLM",
    "StatefulDummyLLM",
    # Gateway
    "LLMGateway",
    "LoadBalanceStrategy",
    "ProviderConfig",
    "get_llm_gateway",
]