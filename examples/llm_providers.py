#!/usr/bin/env python3
"""
VeilArmor - LLM Provider Example

This example demonstrates how to configure and use different
LLM providers with VeilArmor.
"""

import asyncio
import os
from src.llm import (
    LLMGateway,
    LLMProvider,
    LLMRequest,
    Message,
)
from src.llm.gateway import ProviderConfig, LoadBalanceStrategy


async def main():
    """Demonstrate LLM provider configuration."""

    print("=" * 60)
    print("VeilArmor - LLM Provider Example")
    print("=" * 60)

    # Create gateway with a dummy provider for demonstration
    gateway = LLMGateway(
        providers=[
            ProviderConfig(
                name="dummy",
                provider_type=LLMProvider.DUMMY,
                model="dummy",
                priority=1,
            ),
        ],
        strategy=LoadBalanceStrategy.PRIORITY,
    )

    # Example 1: Basic generation with default provider
    print("\n[1] Basic Generation")
    print("    Using default (dummy) provider")

    request = LLMRequest(
        messages=[Message(role="user", content="What is machine learning in one sentence?")],
    )
    response = await gateway.generate(request)
    print(f"    Response: {response.content}")

    # Example 2: Chat completion with conversation history
    print("\n[2] Chat Completion")
    print("    Multi-turn conversation with history")

    messages = [
        Message(role="system", content="You are a helpful coding assistant."),
        Message(role="user", content="What is Python?"),
    ]

    response = await gateway.chat(messages)
    print(f"    Response: {response.content[:100]}...")

    # Example 3: Simple completion helper
    print("\n[3] Simple Completion")
    print("    Using the complete() convenience method")

    response = await gateway.complete(
        prompt="Write a haiku about programming",
        system_prompt="You are a creative poet.",
    )
    print(f"    Response: {response.content}")

    # Example 4: Gateway metrics
    print("\n[4] Gateway Metrics")
    metrics = gateway.get_metrics()
    print(f"    Total requests: {metrics['total_requests']}")
    print(f"    Success rate: {metrics['success_rate']:.0%}")
    print(f"    Providers: {len(metrics['providers'])}")

    print("\n" + "=" * 60)
    print("LLM provider example completed!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
