#!/bin/bash
#===============================================================================
# VeilArmor v2.0 - Git Commit Script
# 
# This script stages and commits all changes for the v2.0 release.
# Branch: v2-fresh-start
#
# DO NOT EXECUTE WITHOUT REVIEWING CHANGES FIRST!
#===============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           VeilArmor v2.0 - Git Commit Script                     ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Navigate to project root
cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)

echo -e "${YELLOW}[1/6] Project root: ${PROJECT_ROOT}${NC}"

#-------------------------------------------------------------------------------
# Step 1: Check if git repo exists
#-------------------------------------------------------------------------------
if [ ! -d ".git" ]; then
    echo -e "${RED}Error: Not a git repository${NC}"
    echo "Initialize with: git init"
    exit 1
fi

echo -e "${GREEN}✓ Git repository found${NC}"

#-------------------------------------------------------------------------------
# Step 2: Create/Switch to v2-fresh-start branch
#-------------------------------------------------------------------------------
echo -e "\n${YELLOW}[2/6] Switching to branch: v2-fresh-start${NC}"

# Check if branch exists
if git show-ref --verify --quiet refs/heads/v2-fresh-start; then
    echo "Branch 'v2-fresh-start' exists, switching to it..."
    git checkout v2-fresh-start
else
    echo "Creating new branch 'v2-fresh-start'..."
    git checkout -b v2-fresh-start
fi

echo -e "${GREEN}✓ Now on branch: $(git branch --show-current)${NC}"

#-------------------------------------------------------------------------------
# Step 3: Add .gitignore updates (exclude __pycache__)
#-------------------------------------------------------------------------------
echo -e "\n${YELLOW}[3/6] Updating .gitignore${NC}"

# Ensure __pycache__ and .pyc files are ignored
if ! grep -q "__pycache__" .gitignore 2>/dev/null; then
    echo "__pycache__/" >> .gitignore
    echo "*.pyc" >> .gitignore
    echo "*.pyo" >> .gitignore
    echo ".pytest_cache/" >> .gitignore
    echo "*.egg-info/" >> .gitignore
    echo -e "${GREEN}✓ Added Python cache patterns to .gitignore${NC}"
fi

#-------------------------------------------------------------------------------
# Step 4: Stage all changes (excluding cache files)
#-------------------------------------------------------------------------------
echo -e "\n${YELLOW}[4/6] Staging changes${NC}"

# Remove cached __pycache__ files from git tracking
git rm -r --cached src/**/__pycache__ 2>/dev/null || true
git rm -r --cached **/__pycache__ 2>/dev/null || true

# Stage all source files by category

echo "  Staging core configuration..."
git add pyproject.toml
git add requirements.txt
git add pytest.ini
git add .env.example
git add config/settings.yaml

echo "  Staging documentation..."
git add README.md
git add INSTALL.md
git add docs/

echo "  Staging Docker files..."
git add Dockerfile
git add docker-compose.yml
git add deploy/

echo "  Staging main application..."
git add main.py
git add src/__init__.py

echo "  Staging API layer..."
git add src/api/__init__.py
git add src/api/models.py
git add src/api/routes.py
git add src/api/server.py
git add src/api/middleware.py

echo "  Staging classifier module..."
git add src/classifier/__init__.py
git add src/classifier/threat_classifier.py
git add src/classifiers/

echo "  Staging core module..."
git add src/core/__init__.py
git add src/core/config.py
git add src/core/pipeline.py
git add src/config/

echo "  Staging LLM module..."
git add src/llm/__init__.py
git add src/llm/base.py
git add src/llm/dummy_llm.py
git add src/llm/gateway.py
git add src/llm/providers.py

echo "  Staging sanitizer module..."
git add src/sanitizer/

echo "  Staging new modules..."
git add src/cache/
git add src/validation/
git add src/processing/
git add src/decision/
git add src/conversation/
git add src/logging/
git add src/sanitization/

echo "  Staging utilities..."
git add src/utils/__init__.py
git add src/utils/exceptions.py
git add src/utils/logger.py
git add src/utils/helpers.py

echo "  Staging tests..."
git add tests/__init__.py
git add tests/test_classifier.py
git add tests/test_pipeline.py
git add tests/test_sanitizer.py

echo "  Staging scripts..."
git add scripts/

echo "  Staging examples..."
git add examples/

echo "  Staging architecture diagram..."
git add System-Architecture.drawio.png 2>/dev/null || true

echo -e "${GREEN}✓ All files staged${NC}"

#-------------------------------------------------------------------------------
# Step 5: Show staged changes summary
#-------------------------------------------------------------------------------
echo -e "\n${YELLOW}[5/6] Staged changes summary${NC}"
echo "─────────────────────────────────────────────────────────────────────"
git diff --cached --stat | tail -30
echo "─────────────────────────────────────────────────────────────────────"

#-------------------------------------------------------------------------------
# Step 6: Commit with detailed message
#-------------------------------------------------------------------------------
echo -e "\n${YELLOW}[6/6] Creating commit${NC}"

git commit -m "feat(v2.0): Complete VeilArmor v2.0 Enterprise LLM Security Framework

🚀 MAJOR RELEASE: VeilArmor v2.0 - Enterprise LLM Security Framework

## Core Features
- Multi-layered security pipeline with 9 processing stages
- Real-time threat classification (prompt injection, jailbreak, PII)
- Enterprise-grade LLM gateway with multi-provider support
- Semantic caching with Redis backend
- Comprehensive input/output sanitization

## Architecture Changes
- Restructured project with modular component design
- Added pyproject.toml with hatchling build system
- Implemented lazy imports to prevent circular dependencies
- Added comprehensive configuration management

## API Layer (src/api/)
- FastAPI-based REST API with OpenAPI documentation
- Request validation with Pydantic models
- Health check, classify, sanitize, and process endpoints
- Middleware for authentication and rate limiting

## Classification Engine (src/classifier/)
- ThreatClassifier with 32 detection rules
- Pattern-based detection for known attack vectors
- Support for: PROMPT_INJECTION, JAILBREAK, PII, HARMFUL_CONTENT
- Severity levels: NONE, LOW, MEDIUM, HIGH, CRITICAL

## Sanitization (src/sanitizer/)
- InputSanitizer: PII removal, URL filtering, normalization
- OutputSanitizer: Response cleaning, sensitive data redaction
- Patterns: Email, SSN, credit card, phone, IP address

## LLM Gateway (src/llm/)
- Multi-provider support: OpenAI, Anthropic, Google, Azure
- Circuit breaker pattern for fault tolerance
- Load balancing strategies: round-robin, random, priority
- Configurable retry with exponential backoff

## New Modules
- src/cache/: Semantic caching with embeddings
- src/validation/: Response quality assurance
- src/processing/: Input preprocessing
- src/decision/: Scoring and decision engine
- src/conversation/: Context management

## Configuration
- YAML-based configuration (config/settings.yaml)
- Environment variable support
- Pydantic settings validation

## CLI & Scripts
- scripts/cli.py: Command-line interface
- scripts/setup.sh: Development environment setup
- Commands: serve, classify, sanitize, process, validate

## Testing
- 27 unit tests (pytest + pytest-asyncio)
- Test coverage for classifier, sanitizer, pipeline
- All tests passing

## Documentation
- Updated README.md with v2.0 features
- Comprehensive INSTALL.md (5 installation methods)
- ARCHITECTURE.md with system design
- API documentation via Swagger UI

## Docker Support
- Multi-stage Dockerfile for production
- docker-compose.yml with Redis integration
- Kubernetes deployment configs in deploy/

## Breaking Changes
- New configuration format (settings.yaml)
- Restructured module imports
- Updated API endpoints

Tested with Python 3.11, 3.12, 3.13"

echo -e "\n${GREEN}════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Commit created successfully!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════════${NC}"

echo -e "\n${BLUE}Current status:${NC}"
git log --oneline -1
echo ""
git status --short

echo -e "\n${YELLOW}Note: git push was NOT executed.${NC}"
echo -e "${YELLOW}To push, run: git push -u origin v2-fresh-start${NC}"
