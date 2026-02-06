"""
VeilArmor - Sanitizer Tests

Tests for input and output sanitization.
"""

import pytest
from unittest.mock import Mock


# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------

@pytest.fixture
def input_sanitizer():
    """Create an input sanitizer instance."""
    from src.sanitization.input_sanitizer import InputSanitizer
    return InputSanitizer()


@pytest.fixture
def output_sanitizer():
    """Create an output sanitizer instance."""
    from src.sanitization.output_sanitizer import OutputSanitizer
    return OutputSanitizer()


# ---------------------------------------------------------------------
# InputSanitizer Tests
# ---------------------------------------------------------------------

class TestInputSanitizer:
    """Tests for InputSanitizer."""

    def test_sanitize_clean_text(self, input_sanitizer):
        """Test sanitization of clean text."""
        text = "Hello, how can I help you?"
        result = input_sanitizer.sanitize(text)
        assert result.sanitized_text is not None

    def test_sanitize_email(self, input_sanitizer):
        """Test sanitization of email addresses."""
        text = "My email is john.doe@example.com"
        result = input_sanitizer.sanitize(text)
        assert result.sanitized_text is not None

    def test_sanitize_credit_card(self, input_sanitizer):
        """Test sanitization of credit card numbers."""
        text = "My card is 4111-1111-1111-1111"
        result = input_sanitizer.sanitize(text)
        assert result.sanitized_text is not None

    def test_sanitize_ssn(self, input_sanitizer):
        """Test sanitization of SSN."""
        text = "My SSN is 123-45-6789"
        result = input_sanitizer.sanitize(text)
        assert result.sanitized_text is not None

    def test_sanitize_phone(self, input_sanitizer):
        """Test sanitization of phone numbers."""
        text = "Call me at (555) 123-4567"
        result = input_sanitizer.sanitize(text)
        assert result.sanitized_text is not None

    def test_sanitize_multiple_pii(self, input_sanitizer):
        """Test sanitization of multiple PII elements."""
        text = "Email: test@example.com, Card: 4111-1111-1111-1111"
        result = input_sanitizer.sanitize(text)
        assert result.sanitized_text is not None


# ---------------------------------------------------------------------
# OutputSanitizer Tests
# ---------------------------------------------------------------------

class TestOutputSanitizer:
    """Tests for OutputSanitizer."""

    def test_sanitize_clean_output(self, output_sanitizer):
        """Test sanitization of clean output."""
        text = "Here is the answer you requested."
        result = output_sanitizer.sanitize(text)
        assert result.sanitized_text is not None

    def test_sanitize_output_with_email(self, output_sanitizer):
        """Test sanitization of output containing email."""
        text = "Contact user@example.com for support."
        result = output_sanitizer.sanitize(text)
        assert result.sanitized_text is not None

    def test_sanitize_output_with_card(self, output_sanitizer):
        """Test sanitization of output containing credit card."""
        text = "Your card number is 4111-1111-1111-1111"
        result = output_sanitizer.sanitize(text)
        assert result.sanitized_text is not None
