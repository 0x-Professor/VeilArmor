# Modal Armor Setup Script
# Run this script to set up your Modal Armor environment

Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  🛡️  Modal Armor Setup Script" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# Check Python version
Write-Host "[1/7] Checking Python version..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "❌ Python not found. Please install Python 3.8 or higher." -ForegroundColor Red
    exit 1
}

# Check YARA
Write-Host ""
Write-Host "[2/7] Checking YARA installation..." -ForegroundColor Yellow
$yaraVersion = yara --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ YARA found: $yaraVersion" -ForegroundColor Green
} else {
    Write-Host "⚠️  YARA not found. Please install YARA from:" -ForegroundColor Yellow
    Write-Host "   https://github.com/VirusTotal/yara/releases/tag/v4.3.2" -ForegroundColor Yellow
    Write-Host ""
    $continue = Read-Host "Continue anyway? (y/n)"
    if ($continue -ne "y") {
        exit 1
    }
}

# Create virtual environment
Write-Host ""
Write-Host "[3/7] Creating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "⚠️  Virtual environment already exists" -ForegroundColor Yellow
} else {
    python -m venv venv
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Virtual environment created" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to create virtual environment" -ForegroundColor Red
        exit 1
    }
}

# Activate virtual environment
Write-Host ""
Write-Host "[4/7] Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"
Write-Host "✅ Virtual environment activated" -ForegroundColor Green

# Install dependencies
Write-Host ""
Write-Host "[5/7] Installing dependencies..." -ForegroundColor Yellow
Write-Host "   This may take a few minutes..." -ForegroundColor Gray
pip install -r requirements.txt --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "❌ Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Setup environment file
Write-Host ""
Write-Host "[6/7] Setting up environment configuration..." -ForegroundColor Yellow
if (Test-Path ".env") {
    Write-Host "⚠️  .env file already exists" -ForegroundColor Yellow
} else {
    Copy-Item ".env.example" ".env"
    Write-Host "✅ Created .env file (please edit with your API keys)" -ForegroundColor Green
}

# Create necessary directories
Write-Host ""
Write-Host "[7/7] Creating directories..." -ForegroundColor Yellow
$dirs = @("logs", "data\vectordb", "data\yara_rules", "data\datasets")
foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}
Write-Host "✅ Directories created" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  ✅ Setup Complete!" -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Edit .env file with your API keys (if using OpenAI):" -ForegroundColor White
Write-Host "   notepad .env" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Load threat detection patterns:" -ForegroundColor White
Write-Host "   python scripts\load_datasets.py --config config\server.conf --default" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Test the installation:" -ForegroundColor White
Write-Host "   python scripts\test_scanner.py --all" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Run basic example:" -ForegroundColor White
Write-Host "   python examples\basic_usage.py" -ForegroundColor Gray
Write-Host ""
Write-Host "5. Start the API server:" -ForegroundColor White
Write-Host "   python src\server.py" -ForegroundColor Gray
Write-Host ""
Write-Host "📚 Documentation:" -ForegroundColor Yellow
Write-Host "   - README.md - Complete documentation" -ForegroundColor Gray
Write-Host "   - GETTING_STARTED.md - Detailed setup guide" -ForegroundColor Gray
Write-Host "   - QUICKSTART.md - Quick reference" -ForegroundColor Gray
Write-Host "   - PROJECT_SUMMARY.md - Project overview" -ForegroundColor Gray
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan

# Offer to load datasets
Write-Host ""
$loadDatasets = Read-Host "Would you like to load default threat patterns now? (y/n)"
if ($loadDatasets -eq "y") {
    Write-Host ""
    Write-Host "Loading datasets..." -ForegroundColor Yellow
    python scripts\load_datasets.py --config config\server.conf --default
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✅ Datasets loaded successfully!" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "⚠️  Dataset loading failed. You can try again later with:" -ForegroundColor Yellow
        Write-Host "   python scripts\load_datasets.py --config config\server.conf --default" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "🛡️  Modal Armor is ready to protect your LLM applications!" -ForegroundColor Green
Write-Host ""
