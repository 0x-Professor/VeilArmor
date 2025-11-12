#  Complete Installation Guide - Modal Armor

This guide covers installation of Modal Armor and all dependencies for implementing the 10 OWASP LLM vulnerabilities.

##  Prerequisites

- **Python 3.8+** (3.10+ recommended)
- **Windows PowerShell** (Admin rights for system installations)
- **Git** (optional, for cloning)
- **Internet connection** (for downloading packages)

---

##  Installation Steps

### Step 1: System Dependencies

#### 1.1 Install YARA (Required for LLM01)

YARA must be installed **before** yara-python package.

**Windows:**
```powershell
# Method 1: Download from GitHub
# Visit: https://github.com/VirusTotal/yara/releases/tag/v4.3.2
# Download: yara-4.3.2-win64.zip
# Extract to C:\yara
# Add C:\yara to PATH

# Method 2: Using Chocolatey
choco install yara

# Verify installation
yara --version
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install yara

# Fedora/RHEL
sudo dnf install yara
```

**macOS:**
```bash
brew install yara
```

#### 1.2 Install Trivy (Required for LLM03)

Trivy is used for supply chain vulnerability scanning.

**Windows:**
```powershell
# Method 1: Using Chocolatey
choco install trivy

# Method 2: Download binary
# Visit: https://github.com/aquasecurity/trivy/releases
# Download: trivy_<version>_Windows-64bit.zip
# Extract and add to PATH

# Verify installation
trivy --version
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install wget
wget https://github.com/aquasecurity/trivy/releases/download/v0.48.0/trivy_0.48.0_Linux-64bit.tar.gz
tar zxvf trivy_0.48.0_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```

**macOS:**
```bash
brew install trivy
```

---

### Step 2: Python Environment Setup

```powershell
# Navigate to project directory
cd U:\Project-Practice\modal-armor

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Windows CMD:
venv\Scripts\activate.bat
# Linux/Mac:
source venv/bin/activate

# Upgrade pip
python -m pip install --upgrade pip
```

---

### Step 3: Install Python Dependencies

```powershell
# Install most dependencies from requirements.txt
pip install -r requirements.txt

# This will install everything EXCEPT:
# - vigil-llm (must install from GitHub)
# - System packages (YARA, Trivy already done in Step 1)
```

---

### Step 4: Install Vigil from GitHub (LLM01)

Vigil is not available on PyPI, must install from source:

```powershell
# Install Vigil directly from GitHub
pip install git+https://github.com/deadbits/vigil-llm.git

# Verify installation
python -c "from vigil.vigil import Vigil; print('Vigil installed successfully!')"
```

---

### Step 5: Install spaCy Model (LLM02)

Presidio requires spaCy NER models for PII detection:

```powershell
# Download English language model
python -m spacy download en_core_web_lg

# Verify installation
python -c "import spacy; nlp = spacy.load('en_core_web_lg'); print('spaCy model loaded!')"
```

---

### Step 6: Setup Configuration Files

```powershell
# Create environment file
if (!(Test-Path .env)) {
    Copy-Item .env.example .env
}

# Edit .env with your API keys
notepad .env
```

**Required in `.env`:**
```env
# Gemini API Key (required)
GEMINI_API_KEY=your_gemini_api_key_here

# Optional: Redis for distributed rate limiting
REDIS_URL=redis://localhost:6379/0

# API Authentication
MODAL_ARMOR_API_KEY=your_secret_api_key_here
```

---

### Step 7: Initialize Data Directories

```powershell
# Create necessary directories
New-Item -ItemType Directory -Force -Path @(
    "data/vectordb",
    "data/yara_rules",
    "data/datasets",
    "data/embeddings",
    "logs",
    "data/canary_tokens"
)

# Load threat patterns (Vigil datasets)
# python scripts/load_datasets.py --config config/server.conf --default
```

---

### Step 8: Verify Installation

```powershell
# Run verification script
python -c "
import sys
print('Python version:', sys.version)

# Check core dependencies
try:
    from vigil.vigil import Vigil
    print(' Vigil: OK')
except Exception as e:
    print(' Vigil:', e)

try:
    from google import genai
    print(' Gemini SDK: OK')
except Exception as e:
    print(' Gemini SDK:', e)

try:
    from presidio_analyzer import AnalyzerEngine
    print(' Presidio: OK')
except Exception as e:
    print(' Presidio:', e)

try:
    from guardrails import Guard
    print(' Guardrails AI: OK')
except Exception as e:
    print(' Guardrails AI:', e)

try:
    import yara
    print(' YARA: OK')
except Exception as e:
    print(' YARA:', e)

try:
    from slowapi import Limiter
    print(' SlowAPI: OK')
except Exception as e:
    print(' SlowAPI:', e)

try:
    import chromadb
    print(' ChromaDB: OK')
except Exception as e:
    print(' ChromaDB:', e)

print('\n Installation verification complete!')
"
```

---

##  Test Installation

```powershell
# Test basic functionality
python tests/test_installation.py

# Start development server
uvicorn src.server:app --reload --host 127.0.0.1 --port 5000

# Visit API documentation
# Open browser: http://127.0.0.1:5000/docs
```

---

##  Troubleshooting

### Issue: "yara-python installation fails"
**Solution:**
```powershell
# Ensure system YARA is installed first
yara --version

# If not found, install YARA (see Step 1.1)
# Then install yara-python
pip install yara-python
```

### Issue: "No module named 'vigil'"
**Solution:**
```powershell
# Vigil is not on PyPI, install from GitHub
pip install git+https://github.com/deadbits/vigil-llm.git
```

### Issue: "google.genai module not found"
**Solution:**
```powershell
# Make sure you're using NEW Gemini SDK (not google-generativeai)
pip uninstall google-generativeai  # Remove old SDK
pip install google-genai           # Install new SDK
```

### Issue: "Presidio: No module named 'en_core_web_lg'"
**Solution:**
```powershell
# Download spaCy English model
python -m spacy download en_core_web_lg
```

### Issue: "Trivy command not found"
**Solution:**
```powershell
# Install Trivy system package (see Step 1.2)
# Add to PATH if installed manually
```

### Issue: "Permission denied installing packages"
**Solution:**
```powershell
# Use virtual environment (recommended)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Or install with --user flag
pip install --user -r requirements.txt
```

---

##  Next Steps

1. **Configure Gemini API**: Add your `GEMINI_API_KEY` to `.env`
2. **Load YARA Rules**: Place custom `.yar` files in `data/yara_rules/`
3. **Initialize Vector DB**: Run dataset loader for Vigil patterns
4. **Start Server**: `uvicorn src.server:app --host 0.0.0.0 --port 5000`
5. **Read Documentation**: Check `README.md` and `GETTING_STARTED.md`

---

##  Additional Resources

- **Vigil GitHub**: https://github.com/deadbits/vigil-llm
- **Gemini API Docs**: https://ai.google.dev/gemini-api/docs
- **Presidio Docs**: https://microsoft.github.io/presidio/
- **Guardrails AI**: https://www.guardrailsai.com/docs
- **YARA Documentation**: https://yara.readthedocs.io/
- **Trivy Documentation**: https://trivy.dev/

---

##  Pro Tips

1. **Use Python 3.10+** for best compatibility
2. **Install in virtual environment** to avoid conflicts
3. **System packages first** (YARA, Trivy), then Python packages
4. **Test incrementally** after each major step
5. **Keep logs** of any errors for troubleshooting

Happy securing! 
