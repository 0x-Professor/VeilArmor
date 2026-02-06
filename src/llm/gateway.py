"""
VeilArmor - LLM Gateway

Routes requests to appropriate LLM provider with load balancing,
fallback, and circuit breaker support.
"""

import asyncio
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Dict, List, Optional

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
from src.llm.dummy_llm import DummyLLM
from src.utils.logger import get_logger

logger = get_logger(__name__)


class LoadBalanceStrategy(str, Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    LEAST_LATENCY = "least_latency"
    PRIORITY = "priority"


@dataclass
class ProviderConfig:
    """Provider configuration."""
    name: str
    provider_type: LLMProvider
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    priority: int = 1
    weight: float = 1.0
    timeout: float = 60.0
    max_retries: int = 3
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "provider_type": self.provider_type.value,
            "model": self.model,
            "priority": self.priority,
            "weight": self.weight,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "enabled": self.enabled,
        }


@dataclass
class CircuitBreaker:
    """Circuit breaker for provider failure handling."""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    failures: int = 0
    last_failure_time: float = 0.0
    state: str = "closed"  # closed, open, half-open
    
    def record_failure(self) -> None:
        """Record a failure."""
        self.failures += 1
        self.last_failure_time = time.time()
        
        if self.failures >= self.failure_threshold:
            self.state = "open"
            logger.warning(
                "Circuit breaker opened",
                failures=self.failures,
            )
    
    def record_success(self) -> None:
        """Record a success."""
        self.failures = 0
        self.state = "closed"
    
    def can_attempt(self) -> bool:
        """Check if attempt is allowed."""
        if self.state == "closed":
            return True
        
        if self.state == "open":
            # Check if recovery timeout has passed
            if time.time() - self.last_failure_time >= self.recovery_timeout:
                self.state = "half-open"
                return True
            return False
        
        # Half-open: allow one attempt
        return True
    
    def reset(self) -> None:
        """Reset circuit breaker."""
        self.failures = 0
        self.last_failure_time = 0.0
        self.state = "closed"


@dataclass
class ProviderState:
    """Runtime state for a provider."""
    config: ProviderConfig
    instance: BaseLLM
    circuit_breaker: CircuitBreaker = field(default_factory=CircuitBreaker)
    total_requests: int = 0
    total_failures: int = 0
    total_latency: float = 0.0
    
    @property
    def avg_latency(self) -> float:
        """Get average latency."""
        if self.total_requests == 0:
            return 0.0
        return self.total_latency / self.total_requests
    
    @property
    def is_available(self) -> bool:
        """Check if provider is available."""
        return (
            self.config.enabled
            and self.instance.is_available()
            and self.circuit_breaker.can_attempt()
        )


class LLMGateway:
    """
    Gateway for LLM providers with load balancing and failover.
    
    Features:
    - Multi-provider support
    - Load balancing (round-robin, random, least-latency, priority)
    - Automatic failover
    - Circuit breaker for fault tolerance
    - Request/response metrics
    """
    
    def __init__(
        self,
        providers: Optional[List[ProviderConfig]] = None,
        strategy: LoadBalanceStrategy = LoadBalanceStrategy.PRIORITY,
        enable_fallback: bool = True,
        default_timeout: float = 60.0,
    ):
        """
        Initialize LLM Gateway.
        
        Args:
            providers: List of provider configurations
            strategy: Load balancing strategy
            enable_fallback: Enable automatic fallback
            default_timeout: Default request timeout
        """
        self.strategy = strategy
        self.enable_fallback = enable_fallback
        self.default_timeout = default_timeout
        
        self._providers: Dict[str, ProviderState] = {}
        self._round_robin_index = 0
        
        # Initialize providers
        if providers:
            for config in providers:
                self.add_provider(config)
        
        logger.info(
            "LLM Gateway initialized",
            strategy=strategy.value,
            providers=len(self._providers),
        )
    
    def add_provider(self, config: ProviderConfig) -> None:
        """
        Add a provider to the gateway.
        
        Args:
            config: Provider configuration
        """
        instance = self._create_provider_instance(config)
        
        self._providers[config.name] = ProviderState(
            config=config,
            instance=instance,
        )
        
        logger.info(
            "Provider added",
            name=config.name,
            provider=config.provider_type.value,
            model=config.model,
        )
    
    def _create_provider_instance(self, config: ProviderConfig) -> BaseLLM:
        """Create provider instance from config."""
        provider_map = {
            LLMProvider.OPENAI: OpenAIProvider,
            LLMProvider.ANTHROPIC: AnthropicProvider,
            LLMProvider.GOOGLE: GoogleProvider,
            LLMProvider.AZURE: AzureOpenAIProvider,
            LLMProvider.OLLAMA: OllamaProvider,
            LLMProvider.DUMMY: DummyLLM,
        }
        
        provider_class = provider_map.get(config.provider_type, LiteLLMProvider)
        
        if config.provider_type == LLMProvider.DUMMY:
            return provider_class()
        
        return provider_class(
            model=config.model,
            api_key=config.api_key,
            base_url=config.base_url,
            timeout=config.timeout,
            max_retries=config.max_retries,
        )
    
    def remove_provider(self, name: str) -> bool:
        """Remove a provider."""
        if name in self._providers:
            del self._providers[name]
            logger.info("Provider removed", name=name)
            return True
        return False
    
    def enable_provider(self, name: str) -> bool:
        """Enable a provider."""
        if name in self._providers:
            self._providers[name].config.enabled = True
            return True
        return False
    
    def disable_provider(self, name: str) -> bool:
        """Disable a provider."""
        if name in self._providers:
            self._providers[name].config.enabled = False
            return True
        return False
    
    def _select_provider(self) -> Optional[ProviderState]:
        """Select a provider based on strategy."""
        available = [
            p for p in self._providers.values()
            if p.is_available
        ]
        
        if not available:
            return None
        
        if self.strategy == LoadBalanceStrategy.ROUND_ROBIN:
            self._round_robin_index = (
                self._round_robin_index % len(available)
            )
            provider = available[self._round_robin_index]
            self._round_robin_index += 1
            return provider
        
        elif self.strategy == LoadBalanceStrategy.RANDOM:
            # Weighted random selection
            weights = [p.config.weight for p in available]
            return random.choices(available, weights=weights, k=1)[0]
        
        elif self.strategy == LoadBalanceStrategy.LEAST_LATENCY:
            # Select provider with lowest average latency
            return min(available, key=lambda p: p.avg_latency or float('inf'))
        
        elif self.strategy == LoadBalanceStrategy.PRIORITY:
            # Select provider with highest priority (lowest number)
            return min(available, key=lambda p: p.config.priority)
        
        return available[0] if available else None
    
    def _get_fallback_providers(
        self,
        exclude: Optional[str] = None,
    ) -> List[ProviderState]:
        """Get fallback providers."""
        return sorted(
            [
                p for p in self._providers.values()
                if p.is_available and p.config.name != exclude
            ],
            key=lambda p: p.config.priority,
        )
    
    async def generate(
        self,
        request: LLMRequest,
        provider_name: Optional[str] = None,
    ) -> LLMResponse:
        """
        Generate response from LLM.
        
        Args:
            request: LLM request
            provider_name: Specific provider to use
            
        Returns:
            LLM response
        """
        # Select provider
        if provider_name:
            provider = self._providers.get(provider_name)
            if not provider:
                raise ValueError(f"Provider not found: {provider_name}")
            if not provider.is_available:
                raise RuntimeError(f"Provider not available: {provider_name}")
        else:
            provider = self._select_provider()
            if not provider:
                raise RuntimeError("No available providers")
        
        # Attempt request with fallback
        attempted = set()
        last_error = None
        
        while provider and provider.config.name not in attempted:
            attempted.add(provider.config.name)
            
            try:
                start_time = time.time()
                
                response = await provider.instance.generate(request)
                
                latency = (time.time() - start_time) * 1000
                
                # Update metrics
                provider.total_requests += 1
                provider.total_latency += latency
                provider.circuit_breaker.record_success()
                
                logger.debug(
                    "LLM request successful",
                    provider=provider.config.name,
                    latency_ms=latency,
                )
                
                return response
                
            except Exception as e:
                last_error = e
                provider.total_failures += 1
                provider.circuit_breaker.record_failure()
                
                logger.warning(
                    "LLM request failed, attempting fallback",
                    provider=provider.config.name,
                    error=str(e),
                )
                
                if not self.enable_fallback:
                    break
                
                # Get next fallback provider
                fallbacks = self._get_fallback_providers(
                    exclude=provider.config.name
                )
                fallbacks = [
                    f for f in fallbacks
                    if f.config.name not in attempted
                ]
                
                provider = fallbacks[0] if fallbacks else None
        
        # All providers failed
        raise RuntimeError(
            f"All providers failed. Last error: {last_error}"
        )
    
    async def generate_stream(
        self,
        request: LLMRequest,
        provider_name: Optional[str] = None,
    ) -> AsyncIterator[StreamChunk]:
        """
        Generate streaming response from LLM.
        
        Args:
            request: LLM request
            provider_name: Specific provider to use
            
        Yields:
            Stream chunks
        """
        # Select provider
        if provider_name:
            provider = self._providers.get(provider_name)
            if not provider:
                raise ValueError(f"Provider not found: {provider_name}")
        else:
            provider = self._select_provider()
            if not provider:
                raise RuntimeError("No available providers")
        
        try:
            async for chunk in provider.instance.generate_stream(request):
                yield chunk
                
            provider.circuit_breaker.record_success()
            
        except Exception as e:
            provider.circuit_breaker.record_failure()
            raise
    
    async def chat(
        self,
        messages: List[Message],
        provider_name: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """
        Chat completion convenience method.
        
        Args:
            messages: List of messages
            provider_name: Specific provider to use
            **kwargs: Additional request parameters
            
        Returns:
            LLM response
        """
        request = LLMRequest(messages=messages, **kwargs)
        return await self.generate(request, provider_name)
    
    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        provider_name: Optional[str] = None,
        **kwargs,
    ) -> LLMResponse:
        """
        Simple completion convenience method.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            provider_name: Specific provider to use
            **kwargs: Additional request parameters
            
        Returns:
            LLM response
        """
        messages = []
        
        if system_prompt:
            messages.append(Message(role="system", content=system_prompt))
        
        messages.append(Message(role="user", content=prompt))
        
        return await self.chat(messages, provider_name, **kwargs)
    
    def get_providers(self) -> List[Dict[str, Any]]:
        """Get list of all providers."""
        return [
            {
                **p.config.to_dict(),
                "available": p.is_available,
                "total_requests": p.total_requests,
                "total_failures": p.total_failures,
                "avg_latency_ms": p.avg_latency,
                "circuit_breaker_state": p.circuit_breaker.state,
            }
            for p in self._providers.values()
        ]
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get gateway metrics."""
        total_requests = sum(p.total_requests for p in self._providers.values())
        total_failures = sum(p.total_failures for p in self._providers.values())
        
        return {
            "total_requests": total_requests,
            "total_failures": total_failures,
            "success_rate": (
                (total_requests - total_failures) / total_requests
                if total_requests > 0
                else 0.0
            ),
            "providers": self.get_providers(),
        }
    
    def reset_metrics(self) -> None:
        """Reset all metrics."""
        for provider in self._providers.values():
            provider.total_requests = 0
            provider.total_failures = 0
            provider.total_latency = 0.0
            provider.circuit_breaker.reset()


def get_llm_gateway(
    config: Optional[Any] = None,
) -> LLMGateway:
    """
    Factory function to get LLM gateway instance.
    
    Args:
        config: Optional Settings object or configuration dictionary
        
    Returns:
        LLM gateway instance
    """
    if config is None:
        # Default configuration with dummy provider
        return LLMGateway(
            providers=[
                ProviderConfig(
                    name="default",
                    provider_type=LLMProvider.DUMMY,
                    model="dummy",
                )
            ]
        )
    
    # Check if config is a Settings object
    if hasattr(config, 'llm'):
        # It's a Settings object - extract LLM config
        llm_config = config.llm
        providers = []
        
        # Check for providers in llm_config
        if hasattr(llm_config, 'providers') and llm_config.providers:
            for name, pconfig in llm_config.providers.items():
                if isinstance(pconfig, dict):
                    providers.append(ProviderConfig(
                        name=name,
                        provider_type=LLMProvider(pconfig.get("type", "openai")),
                        model=pconfig.get("model", "gpt-4o-mini"),
                        api_key=pconfig.get("api_key"),
                        base_url=pconfig.get("base_url"),
                        priority=pconfig.get("priority", 1),
                        weight=pconfig.get("weight", 1.0),
                        timeout=pconfig.get("timeout", 60.0),
                        max_retries=pconfig.get("max_retries", 3),
                        enabled=pconfig.get("enabled", True),
                    ))
        
        # If no providers configured, use dummy
        if not providers:
            providers.append(ProviderConfig(
                name="default",
                provider_type=LLMProvider.DUMMY,
                model="dummy",
            ))
        
        strategy = LoadBalanceStrategy.PRIORITY
        if hasattr(llm_config, 'load_balancing') and llm_config.load_balancing:
            strategy_str = getattr(llm_config.load_balancing, 'strategy', 'priority')
            strategy = LoadBalanceStrategy(strategy_str)
        
        return LLMGateway(
            providers=providers,
            strategy=strategy,
            enable_fallback=True,
            default_timeout=getattr(llm_config, 'timeout', 60.0),
        )
    
    # It's a dictionary config
    providers = []
    for pconfig in config.get("providers", []):
        providers.append(ProviderConfig(
            name=pconfig["name"],
            provider_type=LLMProvider(pconfig.get("type", "openai")),
            model=pconfig.get("model", "gpt-4o-mini"),
            api_key=pconfig.get("api_key"),
            base_url=pconfig.get("base_url"),
            priority=pconfig.get("priority", 1),
            weight=pconfig.get("weight", 1.0),
            timeout=pconfig.get("timeout", 60.0),
            max_retries=pconfig.get("max_retries", 3),
            enabled=pconfig.get("enabled", True),
        ))
    
    if not providers:
        providers.append(ProviderConfig(
            name="default",
            provider_type=LLMProvider.DUMMY,
            model="dummy",
        ))
    
    strategy = LoadBalanceStrategy(config.get("strategy", "priority"))
    
    return LLMGateway(
        providers=providers,
        strategy=strategy,
        enable_fallback=config.get("enable_fallback", True),
        default_timeout=config.get("default_timeout", 60.0),
    )
