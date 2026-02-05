#!/bin/bash
# VeilArmor v2.0 - Development Setup Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           VeilArmor v2.0 - Development Setup                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

cd "$PROJECT_DIR"

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.11"

if [[ "$PYTHON_VERSION" < "$REQUIRED_VERSION" ]]; then
    echo -e "${RED}Error: Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}Python version: $PYTHON_VERSION${NC}"

# Create virtual environment
echo -e "${YELLOW}Creating virtual environment...${NC}"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created${NC}"
else
    echo -e "${GREEN}Virtual environment already exists${NC}"
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt

# Install development dependencies
echo -e "${YELLOW}Installing development dependencies...${NC}"
pip install pytest pytest-asyncio pytest-cov black isort mypy ruff

# Create necessary directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p logs conversations config

# Copy example config if not exists
if [ ! -f "config/settings.yaml" ]; then
    if [ -f "config/settings.example.yaml" ]; then
        cp config/settings.example.yaml config/settings.yaml
        echo -e "${GREEN}Created config/settings.yaml from example${NC}"
    fi
fi

# Create .env file if not exists
if [ ! -f ".env" ]; then
    cat > .env << EOF
# VeilArmor Environment Variables
VEILARMOR_ENV=development
VEILARMOR_LOG_LEVEL=DEBUG

# LLM Provider API Keys (optional)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GOOGLE_API_KEY=

# Redis Configuration (optional)
REDIS_URL=redis://localhost:6379/0
EOF
    echo -e "${GREEN}Created .env file${NC}"
fi

# Make CLI executable
chmod +x scripts/cli.py

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete!                            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "To activate the virtual environment:"
echo "  source venv/bin/activate"
echo ""
echo "To start the server:"
echo "  python main.py"
echo "  # or"
echo "  python scripts/cli.py serve"
echo ""
echo "To run tests:"
echo "  pytest"
echo ""
