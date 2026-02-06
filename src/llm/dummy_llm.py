"""
VeilArmor - Dummy LLM Provider

Testing and development provider that returns mock responses.
"""

import asyncio
import random
import re
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


class DummyLLM(BaseLLM):
    """
    Dummy LLM provider for testing and development.
    
    Returns configurable mock responses without making actual API calls.
    """
    
    DEFAULT_RESPONSES = [
        "This is a mock response from the dummy LLM provider.",
        "I'm a test LLM and I'm here to help with development.",
        "This response is generated for testing purposes only.",
        "The dummy provider is working correctly.",
        "Hello! I'm the VeilArmor test assistant.",
    ]
    
    # Country-capital mappings for demo
    CAPITALS: Dict[str, str] = {
        "france": "Paris",
        "germany": "Berlin",
        "japan": "Tokyo",
        "usa": "Washington, D.C.",
        "uk": "London",
        "italy": "Rome",
        "spain": "Madrid",
        "canada": "Ottawa",
        "australia": "Canberra",
        "india": "New Delhi",
    }
    
    def __init__(
        self,
        responses: Optional[List[str]] = None,
        latency_ms: float = 100.0,
        latency_variance: float = 50.0,
        failure_rate: float = 0.0,
        stream_chunk_size: int = 5,
    ):
        """
        Initialize dummy LLM.
        
        Args:
            responses: Custom response pool
            latency_ms: Simulated latency in milliseconds
            latency_variance: Latency variance
            failure_rate: Probability of simulated failure (0-1)
            stream_chunk_size: Words per streaming chunk
        """
        super().__init__(
            model="dummy-model-v1",
            provider=LLMProvider.DUMMY,
        )
        
        self.responses = responses or self.DEFAULT_RESPONSES
        self.latency_ms = latency_ms
        self.latency_variance = latency_variance
        self.failure_rate = failure_rate
        self.stream_chunk_size = stream_chunk_size
        
        self._request_count = 0
        logger.info("DummyLLM initialized")
    
    async def generate(
        self,
        request: LLMRequest,
    ) -> LLMResponse:
        """
        Generate mock response.
        
        Args:
            request: LLM request
            
        Returns:
            Mock LLM response
        """
        self._request_count += 1
        
        # Simulate latency
        latency = self.latency_ms + random.uniform(
            -self.latency_variance,
            self.latency_variance,
        )
        await asyncio.sleep(latency / 1000)
        
        # Simulate failures
        if random.random() < self.failure_rate:
            raise RuntimeError("Simulated LLM failure")
        
        # Generate response
        response_text = self._generate_response(request)
        
        # Estimate tokens (rough approximation)
        prompt_text = " ".join(m.content for m in request.messages)
        prompt_tokens = len(prompt_text.split())
        completion_tokens = len(response_text.split())
        
        return LLMResponse(
            content=response_text,
            model=self.model,
            provider=self.provider.value,
            finish_reason="stop",
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            latency_ms=latency,
            metadata={
                "dummy": True,
                "request_count": self._request_count,
            },
        )
    
    async def generate_stream(
        self,
        request: LLMRequest,
    ) -> AsyncIterator[StreamChunk]:
        """
        Generate streaming mock response.
        
        Args:
            request: LLM request
            
        Yields:
            Stream chunks
        """
        self._request_count += 1
        
        # Simulate failures
        if random.random() < self.failure_rate:
            raise RuntimeError("Simulated LLM failure")
        
        # Generate response
        response_text = self._generate_response(request)
        words = response_text.split()
        
        # Stream in chunks
        for i in range(0, len(words), self.stream_chunk_size):
            chunk_words = words[i:i + self.stream_chunk_size]
            chunk_text = " ".join(chunk_words)
            
            # Add space if not first chunk
            if i > 0:
                chunk_text = " " + chunk_text
            
            # Simulate streaming latency
            await asyncio.sleep(self.latency_ms / 10 / 1000)
            
            is_final = (i + self.stream_chunk_size) >= len(words)
            
            yield StreamChunk(
                content=chunk_text,
                is_final=is_final,
                finish_reason="stop" if is_final else None,
            )
    
    def _generate_response(self, request: LLMRequest) -> str:
        """Generate response based on request."""
        if not request.messages:
            return random.choice(self.responses)
        
        last_message = request.messages[-1].content
        prompt_lower = last_message.lower()
        
        # Echo request for testing
        if "echo:" in prompt_lower:
            return prompt_lower.replace("echo:", "").strip()
        
        # Check for capital queries
        if "capital" in prompt_lower:
            for country, capital in self.CAPITALS.items():
                if country in prompt_lower:
                    return f"The capital of {country.title()} is {capital}. It's a beautiful city known for its rich history and culture."
            return "I can tell you about the capitals of many countries. Which country are you interested in?"
        
        # Check for greetings
        if any(greet in prompt_lower for greet in ["hello", "hi", "hey", "greetings"]):
            return "Hello! How can I assist you today?"
        
        # Check for help requests
        if "help" in prompt_lower:
            return "I'm here to help! You can ask me questions about various topics, and I'll do my best to assist you."
        
        # Check for weather
        if "weather" in prompt_lower:
            return "I don't have access to real-time weather data, but I can help you find weather information for your location."
        
        # Check for math questions
        if any(op in prompt_lower for op in ["calculate", "what is", "compute", "+"]):
            return self._handle_math(last_message)
        
        # Custom response keywords for testing
        if "error" in prompt_lower and "test" in prompt_lower:
            return "Error: This is a test error response."
        
        if "long" in prompt_lower and "response" in prompt_lower:
            return " ".join(self.DEFAULT_RESPONSES) * 3
        
        if "empty" in prompt_lower:
            return ""
        
        if "json" in prompt_lower:
            return '{"status": "success", "message": "Test JSON response"}'
        
        # Default contextual response
        return self._generate_contextual_response(last_message)
    
    def _handle_math(self, prompt: str) -> str:
        """Handle simple math queries."""
        try:
            numbers = re.findall(r'\d+', prompt)
            if len(numbers) >= 2:
                a, b = int(numbers[0]), int(numbers[1])
                if '+' in prompt or 'plus' in prompt.lower():
                    result = a + b
                elif '-' in prompt or 'minus' in prompt.lower():
                    result = a - b
                elif '*' in prompt or 'times' in prompt.lower() or 'multiply' in prompt.lower():
                    result = a * b
                elif '/' in prompt or 'divided' in prompt.lower():
                    result = a / b if b != 0 else "undefined (division by zero)"
                else:
                    result = a + b
                return f"The result is {result}."
        except Exception:
            pass
        
        return "I can help with calculations. Please provide the numbers and operation you'd like me to compute."
    
    def _generate_contextual_response(self, prompt: str) -> str:
        """Generate a contextual dummy response."""
        prefixes = [
            "Based on my knowledge,",
            "Here's what I can tell you:",
            "That's a great question!",
            "Let me share some information:",
        ]
        
        suffixes = [
            "Is there anything else you'd like to know?",
            "Feel free to ask follow-up questions!",
            "I hope this helps!",
            "Let me know if you need more details.",
        ]
        
        words = prompt.split()[:5]
        topic = " ".join(words) if words else "that"
        
        main_response = f"Regarding '{topic}...', I can provide helpful information on this topic. "
        main_response += "This is a simulated response from the dummy LLM. "
        main_response += "In production, this would be replaced with actual LLM output."
        
        return f"{random.choice(prefixes)} {main_response} {random.choice(suffixes)}"
    
    def set_responses(self, responses: List[str]) -> None:
        """Set custom response pool."""
        self.responses = responses
    
    def add_response(self, response: str) -> None:
        """Add response to pool."""
        self.responses.append(response)
    
    def set_latency(self, latency_ms: float, variance: float = 50.0) -> None:
        """Set simulated latency."""
        self.latency_ms = latency_ms
        self.latency_variance = variance
    
    def set_failure_rate(self, rate: float) -> None:
        """Set simulated failure rate."""
        self.failure_rate = max(0.0, min(1.0, rate))
    
    def get_request_count(self) -> int:
        """Get total request count."""
        return self._request_count
    
    def reset(self) -> None:
        """Reset provider state."""
        self._request_count = 0


class EchoDummyLLM(DummyLLM):
    """Dummy LLM that echoes user input."""
    
    def _generate_response(self, request: LLMRequest) -> str:
        """Echo the last user message."""
        if request.messages:
            for message in reversed(request.messages):
                if message.role == "user":
                    return f"Echo: {message.content}"
        return "No user message to echo."


class TemplatedDummyLLM(DummyLLM):
    """Dummy LLM with template-based responses."""
    
    def __init__(
        self,
        template: str = "Response to: {prompt}",
        **kwargs,
    ):
        """
        Initialize templated dummy LLM.
        
        Args:
            template: Response template with {prompt} placeholder
            **kwargs: Additional arguments
        """
        super().__init__(**kwargs)
        self.template = template
    
    def _generate_response(self, request: LLMRequest) -> str:
        """Generate templated response."""
        prompt = ""
        if request.messages:
            prompt = request.messages[-1].content
        
        return self.template.format(prompt=prompt)


class StatefulDummyLLM(DummyLLM):
    """Dummy LLM that maintains conversation state."""
    
    def __init__(self, **kwargs):
        """Initialize stateful dummy LLM."""
        super().__init__(**kwargs)
        self._conversation_history: List[Dict[str, str]] = []
    
    def _generate_response(self, request: LLMRequest) -> str:
        """Generate response with conversation awareness."""
        for message in request.messages:
            self._conversation_history.append({
                "role": message.role,
                "content": message.content,
            })
        
        turn_count = len([
            m for m in self._conversation_history
            if m["role"] == "user"
        ])
        
        responses = [
            f"This is turn {turn_count} of our conversation.",
            f"I see you've sent {len(self._conversation_history)} messages.",
            "Let me continue our discussion.",
        ]
        
        return random.choice(responses)
    
    def clear_history(self) -> None:
        """Clear conversation history."""
        self._conversation_history = []
    
    def get_history(self) -> List[Dict[str, str]]:
        """Get conversation history."""
        return self._conversation_history.copy()