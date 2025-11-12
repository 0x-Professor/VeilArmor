"""
Test Gemini API Connection
Verifies that the API key works correctly
"""

import os
import requests
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_gemini_api():
    """Test direct API call to Gemini"""
    
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        print("ERROR: GEMINI_API_KEY not found in environment")
        return False
    
    print(f"Testing Gemini API with key: {api_key[:20]}...")
    
    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    
    headers = {
        'Content-Type': 'application/json',
        'X-goog-api-key': api_key
    }
    
    data = {
        "contents": [
            {
                "parts": [
                    {
                        "text": "Explain how AI works in a few words"
                    }
                ]
            }
        ]
    }
    
    try:
        print("\nSending request to Gemini API...")
        response = requests.post(url, headers=headers, json=data)
        
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("\nSUCCESS: API connection verified")
            print("\nResponse:")
            print(json.dumps(result, indent=2))
            
            # Extract and print the text response
            if 'candidates' in result:
                text_response = result['candidates'][0]['content']['parts'][0]['text']
                print("\nGenerated Text:")
                print(text_response)
            
            return True
        else:
            print(f"\nERROR: API request failed")
            print(f"Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        return False


def test_gemini_sdk():
    """Test using the google-genai SDK"""
    
    try:
        from google import genai
        
        api_key = os.getenv("GEMINI_API_KEY")
        client = genai.Client(api_key=api_key)
        
        print("\n" + "="*60)
        print("Testing with google-genai SDK")
        print("="*60)
        
        response = client.models.generate_content(
            model="gemini-2.0-flash-exp",
            contents="Explain how AI works in a few words"
        )
        
        print("\nSUCCESS: SDK connection verified")
        print(f"\nResponse: {response.text}")
        
        return True
        
    except ImportError:
        print("\nWARNING: google-genai SDK not installed")
        print("Install with: uv pip install google-genai")
        return False
    except Exception as e:
        print(f"\nERROR: {str(e)}")
        return False


if __name__ == "__main__":
    print("="*60)
    print("Gemini API Connection Test")
    print("="*60)
    
    # Test direct API call
    test_gemini_api()
    
    # Test SDK
    print("\n")
    test_gemini_sdk()
    
    print("\n" + "="*60)
    print("Test Complete")
    print("="*60)
