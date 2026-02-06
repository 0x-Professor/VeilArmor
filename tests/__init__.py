"""
VeilArmor - Test Suite

Comprehensive test suite for the VeilArmor LLM security framework.

Test Modules:
    - test_classifier: Threat classification tests
    - test_sanitizer: Input/output sanitization tests
    - test_pipeline: Security pipeline tests
    - test_api: FastAPI endpoint tests
    - test_validation: Response validation tests
    - test_cache: Semantic caching tests
    - test_llm: LLM gateway tests
    - test_integration: End-to-end integration tests

Running Tests:
    pytest tests/                    # Run all tests
    pytest tests/test_classifier.py  # Run specific module
    pytest -v                        # Verbose output
    pytest -x                        # Stop on first failure
    pytest --cov=src                 # With coverage
    pytest -m asyncio                # Only async tests
"""

__all__ = [
    "test_classifier",
    "test_sanitizer",
    "test_pipeline",
    "test_api",
    "test_validation",
    "test_cache",
    "test_llm",
    "test_integration",
]
