"""
VeilArmor v2.0 - LiteLLM Provider

Unified LLM provider using LiteLLM for multi-provider support.
"""

import asyncio
import time
from typing import Any, AsyncIterator, Dict, List, Optional

from src.llm.base import (
    BaseLLM,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    Message,
    StreamChunk,
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


class LiteLLMProvider(BaseLLM):
    """
    LLM provider using LiteLLM for unified multi-provider access.
    
    Supports OpenAI, Anthropic, Google, Azure, Cohere, and more.
    """
    
    # Model prefixes for LiteLLM
    PROVIDER_PREFIXES = {
        LLMProvider.OPENAI: "",
        LLMProvider.ANTHROPIC: "anthropic/",
        LLMProvider.GOOGLE: "gemini/",
        LLMProvider.AZURE: "azure/",
        LLMProvider.COHERE: "cohere/",
        LLMProvider.HUGGINGFACE: "huggingface/",
        LLMProvider.OLLAMA: "ollama/",
    }
    
    # Default models per provider
    DEFAULT_MODELS = {
        LLMProvider.OPENAI: "gpt-4o-mini",
        LLMProvider.ANTHROPIC: "claude-3-sonnet-20240229",
        LLMProvider.GOOGLE: "gemini-pro",
        LLMProvider.AZURE: "gpt-4",
        LLMProvider.COHERE: "command",
        LLMProvider.HUGGINGFACE: "mistralai/Mistral-7B-Instruct-v0.1",
        LLMProvider.OLLAMA: "llama2",
    }
    
    def __init__(
        self,
        model: Optional[str] = None,
        provider: LLMProvider = LLMProvider.OPENAI,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: float = 60.0,
        max_retries: int = 3,
        custom_llm_provider: Optional[str] = None,
    ):
        """
        Initialize LiteLLM provider.
        
        Args:
            model: Model identifier
            provider: Provider type
            api_key: API key
            base_url: Custom base URL
            timeout: Request timeout
            max_retries: Max retries
            custom_llm_provider: Custom LiteLLM provider string
        """
        # Determine model
        if model is None:
            model = self.DEFAULT_MODELS.get(provider, "gpt-4o-mini")
        
        super().__init__(
            model=model,
            provider=provider,
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
        )
        
        self.custom_llm_provider = custom_llm_provider
        self._litellm = None
        self._initialized = False
        
        # Request metrics
        self._total_requests = 0
        self._total_tokens = 0
        self._total_latency = 0.0
    
    def _ensure_initialized(self) -> None:
        """Ensure LiteLLM is imported and configured."""
        if self._initialized:
            return
        
        try:
            import litellm
            
            self._litellm = litellm
            
            # Configure LiteLLM
            litellm.set_verbose = False
            litellm.drop_params = True  # Drop unsupported params
            
            # Set API key if provided
            if self.api_key:
                if self.provider == LLMProvider.OPENAI:
                    import os
                    os.environ["OPENAI_API_KEY"] = self.api_key
                elif self.provider == LLMProvider.ANTHROPIC:
                    import os
                    os.environ["ANTHROPIC_API_KEY"] = self.api_key
                elif self.provider == LLMProvider.GOOGLE:
                    import os
                    os.environ["GEMINI_API_KEY"] = self.api_key
            
            self._initialized = True
            logger.info(
                "LiteLLM provider initialized",
                provider=self.provider.value,
                model=self.model,
            )
            
        except ImportError:
            logger.error("LiteLLM not installed. Install with: pip install litellm")
            self._available = False
            raise ImportError("LiteLLM is required. Install with: pip install litellm")
    
    def _get_model_string(self) -> str:
        """Get the model string for LiteLLM."""
        if self.custom_llm_provider:
            return f"{self.custom_llm_provider}/{self.model}"
        
        prefix = self.PROVIDER_PREFIXES.get(self.provider, "")
        return f"{prefix}{self.model}"
    
    async def generate(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        """
        Generate response using LiteLLM.
        
        Args:
            request: LLM request
            
        Returns:
            LLM response
        """
        self._ensure_initialized()
        
        start_time = time.time()
        model_string = request.model or self._get_model_string()
        
        try:
            # Prepare messages
            messages = [m.to_dict() for m in request.messages]
            
            # Build kwargs
            kwargs = {
                "model": model_string,
                "messages": messages,
                "temperature": request.temperature,
                "top_p": request.top_p,
            }
            
            if request.max_tokens is not None:
                kwargs["max_tokens"] = request.max_tokens
            if request.stop:
                kwargs["stop"] = request.stop
            if request.frequency_penalty is not None:
                kwargs["frequency_penalty"] = request.frequency_penalty
            if request.presence_penalty is not None:
                kwargs["presence_penalty"] = request.presence_penalty
            if self.base_url:
                kwargs["base_url"] = self.base_url
            if self.api_key:
                kwargs["api_key"] = self.api_key
            
            # Make async request
            response = await self._litellm.acompletion(**kwargs)
            
            latency_ms = (time.time() - start_time) * 1000
            
            # Extract response data
            content = response.choices[0].message.content
            finish_reason = response.choices[0].finish_reason
            
            # Usage info
            usage = getattr(response, "usage", None)
            prompt_tokens = getattr(usage, "prompt_tokens", 0) if usage else 0
            completion_tokens = getattr(usage, "completion_tokens", 0) if usage else 0
            total_tokens = getattr(usage, "total_tokens", 0) if usage else 0
            
            # Update metrics
            self._total_requests += 1
            self._total_tokens += total_tokens
            self._total_latency += latency_ms
            
            logger.debug(
                "LLM request completed",
                model=model_string,
                latency_ms=latency_ms,
                tokens=total_tokens,
            )
            
            return LLMResponse(
                content=content,
                model=model_string,
                provider=self.provider.value,
                finish_reason=finish_reason,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                latency_ms=latency_ms,
                metadata={
                    "raw_response_id": getattr(response, "id", None),
                },
            )
            
        except Exception as e:
            logger.error(
                "LLM request failed",
                model=model_string,
                error=str(e),
            )
            raise
    
    async def generate_stream(
        self,
        request: LLMRequest,
    ) -> AsyncIterator[StreamChunk]:
        """
        Generate streaming response using LiteLLM.
        
        Args:
            request: LLM request
            
        Yields:
            Stream chunks
        """
        self._ensure_initialized()
        
        model_string = request.model or self._get_model_string()
        
        try:
            # Prepare messages
            messages = [m.to_dict() for m in request.messages]
            
            # Build kwargs
            kwargs = {
                "model": model_string,
                "messages": messages,
                "temperature": request.temperature,
                "top_p": request.top_p,
                "stream": True,
            }
            
            if request.max_tokens:
                kwargs["max_tokens"] = request.max_tokens
            if request.stop:
                kwargs["stop"] = request.stop
            if self.base_url:
                kwargs["base_url"] = self.base_url
            if self.api_key:
                kwargs["api_key"] = self.api_key
            
            # Make streaming request
            response = await self._litellm.acompletion(**kwargs)
            
            async for chunk in response:
                if chunk.choices and chunk.choices[0].delta:
                    content = chunk.choices[0].delta.content or ""
                    finish_reason = chunk.choices[0].finish_reason
                    
                    yield StreamChunk(
                        content=content,
                        is_final=finish_reason is not None,
                        finish_reason=finish_reason,
                    )
            
        except Exception as e:
            logger.error(
                "LLM streaming request failed",
                model=model_string,
                error=str(e),
            )
            raise
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get provider metrics."""
        return {
            "total_requests": self._total_requests,
            "total_tokens": self._total_tokens,
            "total_latency_ms": self._total_latency,
            "avg_latency_ms": (
                self._total_latency / self._total_requests
                if self._total_requests > 0
                else 0.0
            ),
            "avg_tokens_per_request": (
                self._total_tokens / self._total_requests
                if self._total_requests > 0
                else 0.0
            ),
        }
    
    def reset_metrics(self) -> None:
        """Reset metrics."""
        self._total_requests = 0
        self._total_tokens = 0
        self._total_latency = 0.0


class OpenAIProvider(LiteLLMProvider):
    """OpenAI-specific provider."""
    
    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        **kwargs,
    ):
        """Initialize OpenAI provider."""
        super().__init__(
            model=model,
            provider=LLMProvider.OPENAI,
            api_key=api_key,
            **kwargs,
        )


class AnthropicProvider(LiteLLMProvider):
    """Anthropic (Claude) provider."""
    
    def __init__(
        self,
        model: str = "claude-3-sonnet-20240229",
        api_key: Optional[str] = None,
        **kwargs,
    ):
        """Initialize Anthropic provider."""
        super().__init__(
            model=model,
            provider=LLMProvider.ANTHROPIC,
            api_key=api_key,
            **kwargs,
        )


class GoogleProvider(LiteLLMProvider):
    """Google (Gemini) provider."""
    
    def __init__(
        self,
        model: str = "gemini-pro",
        api_key: Optional[str] = None,
        **kwargs,
    ):
        """Initialize Google provider."""
        super().__init__(
            model=model,
            provider=LLMProvider.GOOGLE,
            api_key=api_key,
            **kwargs,
        )


class AzureOpenAIProvider(LiteLLMProvider):
    """Azure OpenAI provider."""
    
    def __init__(
        self,
        model: str = "gpt-4",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        api_version: str = "2024-02-15-preview",
        **kwargs,
    ):
        """Initialize Azure OpenAI provider."""
        super().__init__(
            model=model,
            provider=LLMProvider.AZURE,
            api_key=api_key,
            base_url=base_url,
            **kwargs,
        )
        self.api_version = api_version


class OllamaProvider(LiteLLMProvider):
    """Ollama (local) provider."""
    
    def __init__(
        self,
        model: str = "llama2",
        base_url: str = "http://localhost:11434",
        **kwargs,
    ):
        """Initialize Ollama provider."""
        super().__init__(
            model=model,
            provider=LLMProvider.OLLAMA,
            base_url=base_url,
            **kwargs,
        )
