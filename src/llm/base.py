"""Base LLM interface"""

from abc import ABC, abstractmethod


class BaseLLM(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    async def generate(self, prompt: str) -> str:
        """
        Generate response from LLM.
        
        Args:
            prompt: User prompt
            
        Returns:
            LLM response
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if LLM is available"""
        pass