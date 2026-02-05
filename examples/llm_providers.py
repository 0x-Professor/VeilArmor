#!/usr/bin/env python3
"""
VeilArmor v2.0 - LLM Provider Example

This example demonstrates how to configure and use different
LLM providers with VeilArmor.
"""

import asyncio
import os
from src.core.config import Settings
from src.llm import LLMGateway, LLMProvider


async def main():
    """Demonstrate LLM provider configuration."""
    
    print("=" * 60)
    print("VeilArmor v2.0 - LLM Provider Example")
    print("=" * 60)
    
    settings = Settings()
    
    # Create gateway
    gateway = LLMGateway(settings)
    
    # Example 1: Basic generation with default provider
    print("\n[1] Basic Generation")
    print("    Using default provider from configuration")
    
    response = await gateway.generate(
        prompt="What is machine learning in one sentence?",
    )
    print(f"    Response: {response}")
    
    # Example 2: Generation with specific provider
    print("\n[2] Provider-Specific Generation")
    print("    Specify which LLM provider to use")
    
    # Note: Set appropriate API keys in environment or settings
    providers_to_try = ["openai", "anthropic", "dummy"]
    
    for provider_name in providers_to_try:
        try:
            response = await gateway.generate(
                prompt="Hello!",
                provider=provider_name,
            )
            print(f"    {provider_name}: {response[:50]}...")
            break
        except Exception as e:
            print(f"    {provider_name}: Not available ({type(e).__name__})")
    
    # Example 3: Chat completion
    print("\n[3] Chat Completion")
    print("    Multi-turn conversation with history")
    
    messages = [
        {"role": "system", "content": "You are a helpful coding assistant."},
        {"role": "user", "content": "What is Python?"},
        {"role": "assistant", "content": "Python is a high-level programming language."},
        {"role": "user", "content": "Give me a simple example."},
    ]
    
    response = await gateway.chat(messages)
    print(f"    Response: {response[:100]}...")
    
    # Example 4: Custom generation parameters
    print("\n[4] Custom Parameters")
    print("    Control temperature, max_tokens, etc.")
    
    response = await gateway.generate(
        prompt="Write a haiku about programming",
        temperature=0.9,  # More creative
        max_tokens=50,
        top_p=0.95,
    )
    print(f"    Response: {response}")
    
    # Example 5: Adding custom providers
    print("\n[5] Custom Provider Configuration")
    print("    Add providers programmatically")
    
    # Add a custom provider (example with local Ollama)
    custom_provider = LLMProvider(
        name="ollama",
        api_key="",  # Ollama doesn't need API key
        model="llama2",
        base_url="http://localhost:11434",
        priority=1,
    )
    
    gateway.add_provider(custom_provider)
    print(f"    Added custom provider: {custom_provider.name}")
    print(f"    Total providers: {len(gateway.list_providers())}")
    
    # Example 6: Provider health monitoring
    print("\n[6] Provider Health Status")
    print("    Check health of all configured providers")
    
    for provider_name in gateway.list_providers():
        provider = gateway.get_provider(provider_name)
        health = provider.is_healthy()
        latency = provider.average_latency() if hasattr(provider, 'average_latency') else "N/A"
        print(f"    {provider_name}: {'Healthy' if health else 'Unhealthy'} (latency: {latency})")
    
    # Example 7: Load balancing
    print("\n[7] Load Balancing")
    print("    Distribute requests across providers")
    
    # Configure load balancing
    gateway.set_load_balancing_strategy("round_robin")
    
    for i in range(3):
        selected = gateway.select_provider()
        print(f"    Request {i+1}: Routed to {selected.name if selected else 'None'}")
    
    print("\n" + "=" * 60)
    print("LLM provider example completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
