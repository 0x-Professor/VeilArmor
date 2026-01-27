"""Dummy LLM for testing - Simulates LLM responses"""

import random
from typing import Dict, List

from .base import BaseLLM
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DummyLLM(BaseLLM):
    """
    Dummy LLM that returns predefined responses.
    Used for testing the security pipeline without real LLM costs.
    """
    
    def __init__(self):
        logger.info("DummyLLM initialized")
        
        # Predefined responses for common queries
        self.responses: Dict[str, str] = {
            "capital": "The capital of {country} is {capital}. It's a beautiful city known for its rich history and culture.",
            "weather": "I don't have access to real-time weather data, but I can help you find weather information for your location.",
            "help": "I'm here to help! You can ask me questions about various topics, and I'll do my best to assist you.",
            "math": "Let me calculate that for you. The answer is {result}.",
            "greeting": "Hello! How can I assist you today?",
            "default": "That's an interesting question. Let me provide some information about that topic."
        }
        
        # Country-capital mappings for demo
        self.capitals: Dict[str, str] = {
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
    
    async def generate(self, prompt: str) -> str:
        """
        Generate a dummy response based on the prompt.
        
        Args:
            prompt: User prompt
            
        Returns:
            Simulated LLM response
        """
        prompt_lower = prompt.lower()
        
        # Check for capital queries
        if "capital" in prompt_lower:
            for country, capital in self.capitals.items():
                if country in prompt_lower:
                    return self.responses["capital"].format(
                        country=country.title(),
                        capital=capital
                    )
            return "I can tell you about the capitals of many countries. Which country are you interested in?"
        
        # Check for greetings
        if any(greet in prompt_lower for greet in ["hello", "hi", "hey", "greetings"]):
            return self.responses["greeting"]
        
        # Check for help requests
        if "help" in prompt_lower:
            return self.responses["help"]
        
        # Check for weather
        if "weather" in prompt_lower:
            return self.responses["weather"]
        
        # Check for math questions
        if any(op in prompt_lower for op in ["calculate", "what is", "compute", "+"]):
            return self._handle_math(prompt)
        
        # Default response
        return self._generate_contextual_response(prompt)
    
    def _handle_math(self, prompt: str) -> str:
        """Handle simple math queries"""
        # Very basic math handling for demo
        try:
            # Extract numbers and operation (simplified)
            import re
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
                    result = a + b  # Default to addition
                return f"The result is {result}."
        except:
            pass
        
        return "I can help with calculations. Please provide the numbers and operation you'd like me to compute."
    
    def _generate_contextual_response(self, prompt: str) -> str:
        """Generate a contextual dummy response"""
        # Add some variety to responses
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
        
        # Create a response that references the query
        words = prompt.split()[:5]  # First 5 words
        topic = " ".join(words) if words else "that"
        
        main_response = f"Regarding '{topic}...', I can provide helpful information on this topic. "
        main_response += "This is a simulated response from the dummy LLM. "
        main_response += "In production, this would be replaced with actual LLM output."
        
        return f"{random.choice(prefixes)} {main_response} {random.choice(suffixes)}"
    
    def is_available(self) -> bool:
        """Dummy LLM is always available"""
        return True