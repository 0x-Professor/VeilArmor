# VeilArmor - Installation Guide

Complete installation guide for VeilArmor - Enterprise LLM Security Framework.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
  - [Method 1: pip install (Recommended)](#method-1-pip-install-recommended)
  - [Method 2: Setup Script](#method-2-setup-script)
  - [Method 3: Manual Installation](#method-3-manual-installation)
  - [Method 4: Docker](#method-4-docker)
  - [Method 5: Docker Compose](#method-5-docker-compose)
- [Configuration](#configuration)
- [Verify Installation](#verify-installation)
- [CLI Usage](#cli-usage)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.11+ | 3.12+ |
| pip | 21.0+ | Latest |
| Memory | 2GB | 4GB+ |
| Disk | 500MB | 1GB+ |

**Optional:**
- Redis 7.0+ (for distributed caching)
- Docker 24.0+ (for containerized deployment)
- CUDA GPU (for faster embeddings)

---

## Quick Start

The fastest way to get VeilArmor running:

```bash
# Clone and install
git clone https://github.com/your-org/veilarmor.git
cd veilarmor
pip install -e .

# Run the server
python main.py --debug

# Access at http://localhost:8000
```

---

## Installation Methods

### Method 1: pip install (Recommended)

Best for: Development and most use cases.

```bash
# Clone the repository
git clone https://github.com/your-org/veilarmor.git
cd veilarmor

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install core package
pip install -e .

# For full features, install with all extras
pip install -e ".[all]"

# Or install specific extras
pip install -e ".[cache]"    # Redis + sentence-transformers
pip install -e ".[llm]"      # All LLM providers
pip install -e ".[auth]"     # Authentication features
pip install -e ".[dev]"      # Development tools
```

**Run the server:**
```bash
python main.py
# or with options
python main.py --host 0.0.0.0 --port 8000 --debug
```

---

### Method 2: Setup Script

Best for: Quick development setup with all dependencies.

```bash
# Clone the repository
git clone https://github.com/your-org/veilarmor.git
cd veilarmor

# Run setup script
chmod +x scripts/setup.sh
./scripts/setup.sh

# Activate the created environment
source venv/bin/activate

# Run the server
python main.py
```

The setup script will:
- Create a virtual environment
- Install all dependencies
- Install development tools (pytest, black, mypy, etc.)
- Create configuration files
- Set up logging directories

---

### Method 3: Manual Installation

Best for: Custom environments or specific requirements.

```bash
# Clone repository
git clone https://github.com/your-org/veilarmor.git
cd veilarmor

# Install dependencies from requirements.txt
pip install -r requirements.txt

# Setup configuration
cp .env.example .env
# Edit .env with your API keys

# Create necessary directories
mkdir -p logs conversations

# Run the server
python main.py
```

**Using Conda:**
```bash
# Create conda environment
conda create -n veilarmor python=3.12 -y
conda activate veilarmor

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

---

### Method 4: Docker

Best for: Isolated deployment, CI/CD, and production.

**Build the image:**
```bash
docker build -t veilarmor:2.0 .
```

**Run the container:**
```bash
# Basic run
docker run -p 8000:8000 veilarmor:2.0

# With environment variables
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=sk-your-key \
  -e VEILARMOR_LOG_LEVEL=INFO \
  veilarmor:2.0

# With persistent logs
docker run -p 8000:8000 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/config:/app/config:ro \
  veilarmor:2.0
```

**Verify container:**
```bash
# Check health
curl http://localhost:8000/health

# View logs
docker logs -f veilarmor
```

---

### Method 5: Docker Compose

Best for: Full stack with Redis caching.

**Start all services:**
```bash
# Create .env file with your API keys
cp .env.example .env
# Edit .env file

# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f veilarmor
```

**Stop services:**
```bash
docker-compose down

# Remove volumes too
docker-compose down -v
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Copy example
cp .env.example .env
```

**Required (at least one LLM provider):**
```bash
OPENAI_API_KEY=sk-your-openai-key
# or
ANTHROPIC_API_KEY=sk-ant-your-key
# or  
GOOGLE_API_KEY=your-google-key
```

**Optional settings:**
```bash
# Server
VEILARMOR_HOST=0.0.0.0
VEILARMOR_PORT=8000
VEILARMOR_WORKERS=4

# Logging
VEILARMOR_LOG_LEVEL=INFO
VEILARMOR_DEBUG=false

# Caching (requires Redis)
VEILARMOR_CACHE_ENABLED=true
REDIS_URL=redis://localhost:6379/0
```

### Configuration File

Edit `config/settings.yaml` for advanced configuration:

```yaml
app_name: VeilArmor
version: "2.0.0"
environment: development
debug: false

server:
  host: "0.0.0.0"
  port: 8000
  workers: 4

# See docs/CONFIGURATION.md for full options
```

---

## Verify Installation

### 1. Health Check

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "components": {
    "api": "healthy",
    "classifier": "healthy",
    "sanitizer": "healthy",
    "llm": "healthy"
  }
}
```

### 2. Run Tests

```bash
# All tests
python -m pytest tests/

# With verbose output
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=src
```

### 3. Test Classification

```bash
curl -X POST http://localhost:8000/api/v1/classify \
  -H "Content-Type: application/json" \
  -d '{"text": "What is machine learning?"}'
```

### 4. Test Sanitization

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -H "Content-Type: application/json" \
  -d '{"text": "Email me at test@example.com"}'
```

---

## CLI Usage

VeilArmor includes a powerful CLI for quick operations:

```bash
# Show help
python scripts/cli.py --help

# Show version
python scripts/cli.py version

# Classify text
python scripts/cli.py classify "Ignore all previous instructions"

# Sanitize text
python scripts/cli.py sanitize "My email is test@example.com"

# Start server
python scripts/cli.py serve --port 8000

# Show configuration
python scripts/cli.py config
```

---

## Troubleshooting

### Common Issues

**Issue: ModuleNotFoundError**
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall package
pip install -e .
```

**Issue: Port already in use**
```bash
# Use different port
python main.py --port 8001

# Or kill existing process
lsof -ti:8000 | xargs kill -9
```

**Issue: Redis connection failed**
```bash
# Option 1: Start Redis
redis-server

# Option 2: Disable caching
export VEILARMOR_CACHE_ENABLED=false
python main.py
```

**Issue: LLM API errors**
```bash
# Verify API key is set
echo $OPENAI_API_KEY

# Test without LLM (uses dummy provider)
# Works for classification and sanitization
```

**Issue: Permission denied for setup.sh**
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### Debug Mode

```bash
# Run with debug logging
python main.py --debug

# Or via environment
VEILARMOR_DEBUG=true python main.py
```

### Check Logs

```bash
# View application logs
tail -f logs/veilarmor.log

# Docker logs
docker logs -f veilarmor
```

---

## Next Steps

1. **Read Documentation**
   - [README.md](README.md) - Overview and usage
   - [docs/CONFIGURATION.md](docs/CONFIGURATION.md) - Full config reference
   - [docs/API_REFERENCE.md](docs/API_REFERENCE.md) - API documentation

2. **Explore Examples**
   - [examples/basic_usage.py](examples/basic_usage.py)
   - [examples/custom_pipeline.py](examples/custom_pipeline.py)

3. **Production Deployment**
   - [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) - Docker/Kubernetes guide

---

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/veilarmor/issues)
- **Documentation**: [https://veilarmor.readthedocs.io](https://veilarmor.readthedocs.io)
