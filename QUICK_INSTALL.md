#  Quick Installation Commands - Modal Armor

**Copy and paste these commands to set up Modal Armor with all 10 OWASP LLM vulnerability protections.**

---

## Step 1: System Dependencies

### Windows PowerShell (Run as Administrator)

```powershell
# Download and install YARA manually
# Visit: https://github.com/VirusTotal/yara/releases/tag/v4.3.2
# Download: yara-4.3.2-win64.zip
# Extract to C:\yara and add to PATH

# OR use Chocolatey
choco install yara

# Verify YARA
yara --version

# Optional: Install Trivy for supply chain scanning
choco install trivy
# OR download from: https://github.com/aquasecurity/trivy/releases

# Verify Trivy
trivy --version
```

---

## Step 2: Python Environment

```powershell
# Navigate to project
cd U:\Project-Practice\modal-armor

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Upgrade pip
python -m pip install --upgrade pip
```

---

## Step 3: Install Python Dependencies

```powershell
# Install most dependencies from requirements.txt
pip install -r requirements.txt

# This installs:
# - google-genai (Gemini API)
# - presidio-analyzer, presidio-anonymizer (PII detection)
# - guardrails-ai (output validation)
# - slowapi (rate limiting)
# - scikit-learn (anomaly detection)
# - chromadb, sentence-transformers (vector DB)
# - yara-python (pattern matching)
# - bleach (HTML sanitization)
# - redis (rate limiting storage)
# - And all other dependencies
```

---

## Step 4: Install Vigil (Must install from GitHub)

```powershell
# Vigil is NOT on PyPI, must install from source
pip install git+https://github.com/deadbits/vigil-llm.git

# Verify installation
python -c "from vigil.vigil import Vigil; print(' Vigil installed!')"
```

---

## Step 5: Install spaCy Model for PII Detection

```powershell
# Download English NER model (required by Presidio)
python -m spacy download en_core_web_lg

# Verify installation
python -c "import spacy; nlp = spacy.load('en_core_web_lg'); print(' spaCy model loaded!')"
```

---

## Step 6: Install Guardrails Validators (Optional)

```powershell
# Configure Guardrails
guardrails configure

# Install validators from Guardrails Hub
guardrails hub install hub://guardrails/toxic_language
guardrails hub install hub://guardrails/competitor_check

# Verify installation
python -c "from guardrails import Guard; print(' Guardrails configured!')"
```

---

## Step 7: Configure Environment Variables

```powershell
# Create .env file
if (!(Test-Path .env)) {
    Copy-Item .env.example .env
}

# Edit .env file
notepad .env
```

**Add to `.env`:**
```env
# Required
GEMINI_API_KEY=your_gemini_api_key_here

# Optional
REDIS_URL=redis://localhost:6379/0
MODAL_ARMOR_API_KEY=your_secret_api_key
JWT_SECRET=your_jwt_secret
```

---

## Step 8: Create Data Directories

```powershell
# Create all necessary directories
$dirs = @("data/vectordb", "data/yara_rules", "data/datasets", "data/embeddings", "data/canary_tokens", "logs")
foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
}

Write-Host " Directories created" -ForegroundColor Green
```

---

## Step 9: Verify Complete Installation

```powershell
# Run comprehensive verification
python -c "
import sys
print('Python version:', sys.version)
print('\n Checking dependencies...\n')

checks = []

# Core dependencies
try:
    from vigil.vigil import Vigil
    checks.append(('', 'Vigil (LLM01)', 'OK'))
except Exception as e:
    checks.append(('', 'Vigil (LLM01)', str(e)))

try:
    from google import genai
    checks.append(('', 'Gemini SDK', 'OK'))
except Exception as e:
    checks.append(('', 'Gemini SDK', str(e)))

try:
    from presidio_analyzer import AnalyzerEngine
    checks.append(('', 'Presidio (LLM02)', 'OK'))
except Exception as e:
    checks.append(('', 'Presidio (LLM02)', str(e)))

try:
    from guardrails import Guard
    checks.append(('', 'Guardrails (LLM05)', 'OK'))
except Exception as e:
    checks.append(('', 'Guardrails (LLM05)', str(e)))

try:
    import yara
    checks.append(('', 'YARA', 'OK'))
except Exception as e:
    checks.append(('', 'YARA', str(e)))

try:
    from slowapi import Limiter
    checks.append(('', 'SlowAPI (LLM10)', 'OK'))
except Exception as e:
    checks.append(('', 'SlowAPI (LLM10)', str(e)))

try:
    import chromadb
    checks.append(('', 'ChromaDB (LLM08)', 'OK'))
except Exception as e:
    checks.append(('', 'ChromaDB (LLM08)', str(e)))

try:
    from sklearn.ensemble import IsolationForest
    checks.append(('', 'scikit-learn (LLM04)', 'OK'))
except Exception as e:
    checks.append(('', 'scikit-learn (LLM04)', str(e)))

try:
    import spacy
    nlp = spacy.load('en_core_web_lg')
    checks.append(('', 'spaCy Model', 'OK'))
except Exception as e:
    checks.append(('', 'spaCy Model', 'Run: python -m spacy download en_core_web_lg'))

for status, name, msg in checks:
    print(f'{status} {name}: {msg}')

print('\n Installation verification complete!')
"
```

---

## Step 10: Start Development Server

```powershell
# Start FastAPI server with hot reload
uvicorn src.server:app --host 127.0.0.1 --port 5000 --reload

# Server will be available at:
# - API: http://127.0.0.1:5000
# - Swagger UI: http://127.0.0.1:5000/docs
# - ReDoc: http://127.0.0.1:5000/redoc
```

---

## Step 11: Test with Example Script

```powershell
# Run the complete Gemini integration example
python examples\gemini_integration.py
```

---

##  Troubleshooting Commands

### If YARA fails:

```powershell
# Check if YARA is in PATH
yara --version

# If not found, download manually and add to PATH
$env:Path += ";C:\yara"

# Then install yara-python
pip install yara-python
```

### If Vigil fails:

```powershell
# Try installing with verbose output
pip install -v git+https://github.com/deadbits/vigil-llm.git

# Or clone and install locally
git clone https://github.com/deadbits/vigil-llm.git
cd vigil-llm
pip install -e .
cd ..
```

### If spaCy model fails:

```powershell
# Download with verbose output
python -m spacy download en_core_web_lg --verbose

# Or download manually and link
python -m spacy download en_core_web_lg --user
python -m spacy link en_core_web_lg en
```

### If Redis is not available (optional):

```powershell
# Use in-memory storage for rate limiting
# In config/gemini.conf, set:
# [rate_limit]
# storage_uri = "memory://"

# Or install Redis (Windows):
choco install redis-64
redis-server
```

---

##  Verification Checklist

- [ ] Python 3.8+ installed
- [ ] YARA installed and in PATH
- [ ] Virtual environment created and activated
- [ ] All pip packages installed (requirements.txt)
- [ ] Vigil installed from GitHub
- [ ] spaCy model downloaded
- [ ] Guardrails validators installed (optional)
- [ ] .env file created with GEMINI_API_KEY
- [ ] Data directories created
- [ ] Verification script passes
- [ ] Server starts successfully
- [ ] Example script runs

---

##  Quick Reference

| Component | Install Command | Verify Command |
|-----------|----------------|----------------|
| YARA | `choco install yara` | `yara --version` |
| Trivy | `choco install trivy` | `trivy --version` |
| Python deps | `pip install -r requirements.txt` | `pip list` |
| Vigil | `pip install git+https://github.com/deadbits/vigil-llm.git` | `python -c "from vigil.vigil import Vigil"` |
| spaCy model | `python -m spacy download en_core_web_lg` | `python -c "import spacy; spacy.load('en_core_web_lg')"` |
| Guardrails | `guardrails configure` | `python -c "from guardrails import Guard"` |

---

##  You're Ready!

All 10 OWASP LLM vulnerabilities are now protected:

1.  **LLM01**: Vigil (prompt injection)
2.  **LLM02**: Presidio (PII detection)
3.  **LLM03**: Trivy (supply chain)
4.  **LLM04**: scikit-learn (poisoning)
5.  **LLM05**: Guardrails (output validation)
6.  **LLM06**: Policy enforcement
7.  **LLM07**: Canary tokens
8.  **LLM08**: RAG security
9.  **LLM09**: Gemini fact-checking
10.  **LLM10**: SlowAPI rate limiting

**Start building secure LLM applications! **
