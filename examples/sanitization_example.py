#!/usr/bin/env python3
"""
VeilArmor v2.0 - Sanitization Example

This example demonstrates input and output sanitization.
"""

from src.core.config import Settings
from src.sanitizer import InputSanitizer, OutputSanitizer


def main():
    """Demonstrate sanitization capabilities."""
    
    # Load settings
    settings = Settings()
    
    # Create sanitizers
    input_sanitizer = InputSanitizer(settings)
    output_sanitizer = OutputSanitizer(settings)
    
    print("=" * 60)
    print("VeilArmor v2.0 - Sanitization Example")
    print("=" * 60)
    
    # Input sanitization examples
    print("\n--- INPUT SANITIZATION ---")
    
    input_examples = [
        # PII removal
        ("My SSN is 123-45-6789 and my card is 4111-1111-1111-1111",
         "PII - SSN and Credit Card"),
        
        # Email and phone
        ("Contact me at john.doe@example.com or call 555-123-4567",
         "PII - Email and Phone"),
        
        # URLs
        ("Visit https://malicious-site.com/payload?evil=true for info",
         "URL Sanitization"),
        
        # Mixed content
        ("My password is SuperSecret123! stored at api.example.com",
         "Mixed Sensitive Content"),
        
        # Clean input
        ("What is the weather like today?",
         "Clean Input"),
    ]
    
    for text, description in input_examples:
        print(f"\n[{description}]")
        print(f"  Original: {text}")
        
        result = input_sanitizer.sanitize(text)
        
        print(f"  Sanitized: {result.sanitized_text}")
        print(f"  Modifications: {result.modifications_made}")
        
        if result.redactions:
            print(f"  Redactions: {len(result.redactions)} items")
    
    # Output sanitization examples
    print("\n\n--- OUTPUT SANITIZATION ---")
    
    output_examples = [
        # Sensitive data in response
        ("Here is your password: secretpassword123",
         "Password in Response"),
        
        # PII leakage
        ("The user's SSN is 987-65-4321 and email is private@secret.com",
         "PII Leakage"),
        
        # System information
        ("The database password is stored in /etc/secrets/db.conf",
         "System Information"),
        
        # Clean response
        ("The capital of France is Paris, a beautiful city.",
         "Clean Response"),
    ]
    
    for text, description in output_examples:
        print(f"\n[{description}]")
        print(f"  Original: {text}")
        
        result = output_sanitizer.sanitize(text)
        
        print(f"  Sanitized: {result.sanitized_text}")
        print(f"  Modifications: {result.modifications_made}")
    
    print("\n" + "=" * 60)
    print("Sanitization example completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
