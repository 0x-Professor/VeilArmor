"""LLM Gateway - Routes requests to appropriate LLM provider"""

from typing import Optional

from .base import BaseLLM
from .dummy_llm import DummyLLM
from src.core.config import Settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


class LLMGateway:
    """
    Gateway for LLM providers.
    Routes requests to the configured LLM provider.
    Extensible for adding new providers (OpenAI, Gemini, etc.)
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.provider = self._initialize_provider()
        logger.info(f"LLMGateway initialized with provider: {settings.llm.provider}")
    
    def _initialize_provider(self) -> BaseLLM:
        """Initialize the configured LLM provider"""
        provider_name = self.settings.llm.provider.lower()
        
        if provider_name == "dummy":
            return DummyLLM()
        
        # Future providers can be added here:
        # elif provider_name == "openai":
        #     return OpenAIProvider(self.settings)
        # elif provider_name == "gemini":
        #     return GeminiProvider(self.settings)
        
        else:
            logger.warning(f"Unknown provider '{provider_name}', falling back to dummy")
            return DummyLLM()
    
    async def generate(self, prompt: str) -> str:
        """
        Generate response from LLM.
        
        Args:
            prompt: Sanitized user prompt
            
        Returns:
            LLM response
        """
        if not self.provider.is_available():
            logger.error("LLM provider is not available")
            raise RuntimeError("LLM provider is not available")
        
        logger.debug(f"Sending prompt to LLM: {prompt[:100]}...")
        response = await self.provider.generate(prompt)
        logger.debug(f"Received response: {response[:100]}...")
        
        return response


def get_llm_gateway(settings: Optional[Settings] = None) -> LLMGateway:
    """Factory function to get LLM gateway instance"""
    from src.core.config import get_settings
    return LLMGateway(settings or get_settings())