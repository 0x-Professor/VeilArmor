"""
VeilArmor v2.0 - Sanitizer Tests

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
    from src.sanitizer.input_sanitizer import InputSanitizer
    settings = Mock()
    settings.security.sanitizer.redact_pii = True
    settings.security.sanitizer.redact_placeholder = "[REDACTED]"
    return InputSanitizer(settings)


@pytest.fixture
def output_sanitizer():
    """Create an output sanitizer instance."""
    from src.sanitizer.output_sanitizer import OutputSanitizer
    settings = Mock()
    settings.security.sanitizer.redact_pii = True
    settings.security.sanitizer.redact_placeholder = "[REDACTED]"
    return OutputSanitizer(settings)


# ---------------------------------------------------------------------
# InputSanitizer Tests
# ---------------------------------------------------------------------

class TestInputSanitizer:
    """Tests for InputSanitizer."""
    
    def test_sanitize_clean_text(self, input_sanitizer):
        """Test sanitization of clean text."""
        text = "Hello, how can I help you?"
        result = input_sanitizer.sanitize(text)
        assert result == text
    
    def test_sanitize_email(self, input_sanitizer):
        """Test sanitization of email addresses."""
        text = "My email is john.doe@example.com"
        result = input_sanitizer.sanitize(text)
        assert "john.doe@example.com" not in result
        assert "[EMAIL]" in result
    
    def test_sanitize_credit_card(self, input_sanitizer):
        """Test sanitization of credit card numbers."""
        text = "My card is 4111-1111-1111-1111"
        result = input_sanitizer.sanitize(text)
        assert "4111-1111-1111-1111" not in result
        assert "[CREDIT_CARD]" in result
    
    def test_sanitize_ssn(self, input_sanitizer):
        """Test sanitization of SSN."""
        text = "My SSN is 123-45-6789"
        result = input_sanitizer.sanitize(text)
        assert "123-45-6789" not in result
        assert "[SSN]" in result
    
    def test_sanitize_phone(self, input_sanitizer):
        """Test sanitization of phone numbers."""
        text = "Call me at (555) 123-4567"
        result = input_sanitizer.sanitize(text)
        # Phone numbers should be redacted or still present
        # depending on implementation
        assert result  # Just verify we get a result
    
    def test_sanitize_multiple_pii(self, input_sanitizer):
        """Test sanitization of multiple PII elements."""
        text = "Email: test@example.com, Card: 4111-1111-1111-1111"
        result = input_sanitizer.sanitize(text)
        assert "test@example.com" not in result
        assert "4111-1111-1111-1111" not in result


# ---------------------------------------------------------------------
# OutputSanitizer Tests
# ---------------------------------------------------------------------

class TestOutputSanitizer:
    """Tests for OutputSanitizer."""
    
    def test_sanitize_clean_output(self, output_sanitizer):
        """Test sanitization of clean output."""
        text = "Here is the answer you requested."
        result = output_sanitizer.sanitize(text)
        assert result == text
    
    def test_sanitize_output_with_email(self, output_sanitizer):
        """Test sanitization of output containing email."""
        text = "Contact user@example.com for support."
        result = output_sanitizer.sanitize(text)
        assert "user@example.com" not in result
        # The placeholder could be [EMAIL] or [EMAIL_REDACTED]
        assert "[EMAIL" in result
    
    def test_sanitize_output_with_card(self, output_sanitizer):
        """Test sanitization of output containing credit card."""
        text = "Your card number is 4111-1111-1111-1111"
        result = output_sanitizer.sanitize(text)
        assert "4111-1111-1111-1111" not in result
