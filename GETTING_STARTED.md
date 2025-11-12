#  Getting Started with Modal Armor

This guide will walk you through integrating Modal Armor with Vigil into your project to protect your LLM applications.

##  Table of Contents

1. [Understanding the Architecture](#architecture)
2. [Installation Steps](#installation)
3. [Configuration Guide](#configuration)
4. [Integration Patterns](#integration)
5. [Testing Your Setup](#testing)
6. [Production Deployment](#production)

##  Architecture {#architecture}

Modal Armor is built on the Vigil library and provides multiple layers of defense:

```
User Input
    ↓

  Modal Armor Security Layer         
                                     
    
   Vector DB Scanner                 ← Similarity search
   YARA Pattern Matcher              ← Rule-based detection
   Transformer Model                 ← ML classification
   Similarity Analyzer               ← Response correlation
   Canary Token System              ← Prompt leakage detection
    
                                     
  Risk Score Aggregation             
  Threat Level Classification        

    ↓
 Safe → Pass to LLM
 Threat → Block/Log
```

##  Installation {#installation}

### Step 1: System Prerequisites

**Windows:**
```powershell
# Install Python 3.8 or higher
python --version

# Install YARA
# Download from: https://github.com/VirusTotal/yara/releases/tag/v4.3.2
# Extract to C:\yara and add to PATH
```

**Linux/Mac:**
```bash
# Python
python3 --version

# YARA
sudo apt-get install yara  # Ubuntu/Debian
brew install yara          # macOS
```

### Step 2: Clone and Setup

```powershell
# Navigate to your project
cd u:\Project-Practice\modal-armor

# Create virtual environment
python -m venv venv

# Activate (Windows PowerShell)
.\venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Configure Environment

```powershell
# Copy environment template
copy .env.example .env

# Edit with your settings
notepad .env
```

Add your API keys to `.env`:
```env
OPENAI_API_KEY=your_openai_key_here  # If using OpenAI embeddings
MODAL_ARMOR_API_KEY=your_secret_key   # For API authentication
```

### Step 4: Load Threat Patterns

```powershell
# Load default threat detection patterns
python scripts\load_datasets.py --config config\server.conf --default

# This creates the vector database with known attack patterns
```

##  Configuration Guide {#configuration}

### Basic Configuration (`config/server.conf`)

```toml
[scanners]
# Enable/disable scanners
vectordb_enabled = true      # Similarity-based detection
yara_enabled = true          # Pattern-based detection
transformer_enabled = true   # ML-based detection
similarity_enabled = true    # Response correlation
sentiment_enabled = false    # Sentiment analysis (optional)

# Scanner weights (must sum to 1.0)
vectordb_weight = 0.35
yara_weight = 0.30
transformer_weight = 0.35

[vectordb]
# Embedding model choice
# Local (fast): sentence-transformers/all-MiniLM-L6-v2
# OpenAI (better): text-embedding-ada-002
embedding_model = "sentence-transformers/all-MiniLM-L6-v2"
similarity_threshold = 0.85  # Lower = more sensitive

[transformer]
model_name = "deepset/deberta-v3-base-injection"
threshold = 0.98  # Detection confidence threshold

[yara]
rules_path = "data/yara_rules"
auto_compile = true
```

### Advanced Configuration

For OpenAI embeddings, use `config/openai.conf`:
```toml
[vectordb]
embedding_model = "text-embedding-ada-002"

[openai]
enabled = true
api_key = ""  # Set via OPENAI_API_KEY env var
```

##  Integration Patterns {#integration}

### Pattern 1: Direct Integration (Recommended)

```python
from modal_armor import ModalArmor

# Initialize once at startup
armor = ModalArmor.from_config('config/server.conf')

def protected_llm_call(user_input: str, system_prompt: str):
    """Secure LLM call with Modal Armor protection"""
    
    # 1. Scan user input
    input_result = armor.scan_input(user_input)
    
    if input_result.is_threat:
        # Log the attempt
        print(f" Blocked: {input_result.messages}")
        return "I cannot process this request."
    
    # 2. Add canary to system prompt
    protected_prompt = armor.add_canary(system_prompt)
    
    # 3. Call your LLM
    llm_response = your_llm_function(protected_prompt, user_input)
    
    # 4. Scan output
    output_result = armor.scan_output(user_input, llm_response)
    
    if output_result.is_threat:
        print(f" Output blocked: {output_result.messages}")
        return "I cannot provide that information."
    
    # 5. Check for canary leakage
    if armor.check_canary(llm_response):
        print(" ALERT: System prompt leaked!")
        return "Security violation detected."
    
    # 6. Return safe response
    return llm_response
```

### Pattern 2: FastAPI Middleware

```python
from fastapi import FastAPI, Request, HTTPException
from modal_armor import ModalArmor

app = FastAPI()
armor = ModalArmor.from_config('config/server.conf')

@app.middleware("http")
async def modal_armor_middleware(request: Request, call_next):
    # Check if this is a chat endpoint
    if request.url.path == "/api/chat":
        body = await request.json()
        user_input = body.get("message", "")
        
        # Scan input
        result = armor.scan_input(user_input)
        
        if result.is_threat:
            raise HTTPException(
                status_code=400,
                detail=f"Malicious input detected: {result.messages}"
            )
    
    return await call_next(request)

@app.post("/api/chat")
async def chat(message: str):
    # Your LLM logic here
    response = call_llm(message)
    
    # Scan output
    output_result = armor.scan_output(message, response)
    
    if output_result.is_threat:
        return {"response": "I cannot provide that information."}
    
    return {"response": response}
```

### Pattern 3: Decorator Pattern

```python
from functools import wraps
from modal_armor import ModalArmor

armor = ModalArmor.from_config('config/server.conf')

def llm_protected(func):
    """Decorator to protect LLM functions"""
    @wraps(func)
    def wrapper(prompt: str, *args, **kwargs):
        # Scan input
        result = armor.scan_input(prompt)
        if result.is_threat:
            raise ValueError(f"Malicious input: {result.messages}")
        
        # Call function
        response = func(prompt, *args, **kwargs)
        
        # Scan output
        output_result = armor.scan_output(prompt, response)
        if output_result.is_threat:
            raise ValueError(f"Unsafe output: {output_result.messages}")
        
        return response
    
    return wrapper

@llm_protected
def my_llm_function(prompt: str) -> str:
    # Your LLM call
    return openai.chat.completions.create(...)
```

### Pattern 4: REST API Server

```powershell
# Start the Modal Armor API server
python src\server.py --config config\server.conf --port 5000

# Use from any application
curl -X POST http://localhost:5000/api/v1/analyze/prompt \
  -H "Content-Type: application/json" \
  -d '{"prompt": "user input here"}'
```

##  Testing Your Setup {#testing}

### Test 1: Basic Functionality

```powershell
# Run basic usage example
python examples\basic_usage.py
```

This tests:
-  Safe inputs pass through
-  Malicious inputs are blocked
-  Canary tokens work
-  All scanners are functional

### Test 2: Scanner Performance

```powershell
# Test all attack patterns
python scripts\test_scanner.py --all
```

Expected output:
```
Total Tests: 9
Threats Detected: 8
Allowed: 1
Detection Rate: 88.9%
```

### Test 3: Custom Prompt

```powershell
# Test your own prompt
python scripts\test_scanner.py --prompt "Your test prompt here"
```

### Test 4: OpenAI Integration

```powershell
# Set your API key
$env:OPENAI_API_KEY="your-key-here"

# Run integration test
python examples\openai_integration.py
```

##  Production Deployment {#production}

### Deployment Checklist

- [ ] Set strong API keys in `.env`
- [ ] Use HTTPS for API server
- [ ] Enable rate limiting
- [ ] Configure logging properly
- [ ] Set up monitoring/alerts
- [ ] Use production-grade vector DB (Pinecone/Weaviate)
- [ ] Enable authentication
- [ ] Review and customize YARA rules
- [ ] Set appropriate detection thresholds
- [ ] Implement fallback mechanisms

### Production Configuration

```toml
[app]
debug = false
workers = 4

[security]
api_key_enabled = true
rate_limit_enabled = true
rate_limit_per_minute = 100

[logging]
level = "INFO"
file = "logs/modal_armor.log"
log_detections = true
```

### Running in Production

```powershell
# Using uvicorn with workers
uvicorn src.server:app \
  --host 0.0.0.0 \
  --port 5000 \
  --workers 4 \
  --log-level info

# Or with gunicorn (Linux)
gunicorn src.server:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:5000
```

### Docker Deployment

```dockerfile
FROM python:3.10-slim

# Install YARA
RUN apt-get update && apt-get install -y yara

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Load datasets
RUN python scripts/load_datasets.py --default

# Run server
CMD ["python", "src/server.py", "--host", "0.0.0.0", "--port", "5000"]
```

### Monitoring

```python
# Add to your application
import time

@app.middleware("http")
async def monitor_performance(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    
    # Log slow requests
    if duration > 1.0:
        logger.warning(f"Slow request: {request.url.path} took {duration:.2f}s")
    
    return response
```

##  Performance Tuning

### Optimize for Speed

```toml
[vectordb]
# Use smaller, faster model
embedding_model = "sentence-transformers/all-MiniLM-L6-v2"
top_k = 3  # Fewer similarity checks

[transformer]
device = "cuda"  # Use GPU if available
```

### Optimize for Accuracy

```toml
[vectordb]
# Use better model
embedding_model = "sentence-transformers/all-mpnet-base-v2"
similarity_threshold = 0.90  # Higher threshold
top_k = 10  # More matches

[transformer]
threshold = 0.99  # Higher confidence
```

##  Troubleshooting

### Issue: High False Positives

**Solution:** Adjust thresholds
```toml
[vectordb]
similarity_threshold = 0.90  # Increase from 0.85

[transformer]
threshold = 0.99  # Increase from 0.98
```

### Issue: Missing Detections

**Solution:** Enable more scanners or lower thresholds
```toml
[scanners]
sentiment_enabled = true  # Enable additional scanner

[vectordb]
similarity_threshold = 0.80  # More sensitive
```

### Issue: Slow Performance

**Solution:**
1. Use local embeddings (not OpenAI)
2. Reduce `top_k` value
3. Disable heavy scanners
4. Use GPU for transformer models
5. Implement caching

##  Additional Resources

- **Vigil Documentation**: https://vigil.deadbits.ai/
- **OWASP LLM Top 10**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **Prompt Injection Guide**: https://github.com/jthack/PIPE
- **Custom YARA Rules**: https://yara.readthedocs.io/

##  Support

Need help? 
- Check the main README.md
- Review example files in `examples/`
- Test with `scripts/test_scanner.py`
- Open an issue on GitHub

---

**You're now ready to secure your LLM applications with Modal Armor! **
