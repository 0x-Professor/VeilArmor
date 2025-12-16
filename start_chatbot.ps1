# Modal Armor Secure Chatbot - Startup Script
# Run both the Modal Armor API and the Streamlit chatbot

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Modal Armor Secure Chatbot Startup" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
.\.venv\Scripts\Activate.ps1

# Install chatbot requirements
Write-Host "Installing chatbot requirements..." -ForegroundColor Yellow
pip install -r chatbot/requirements.txt -q

# Set environment variables
Write-Host "Setting environment variables..." -ForegroundColor Yellow
$env:HF_TOKEN = "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"
$env:MODAL_ARMOR_API_URL = "http://localhost:8000"

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Starting Services..." -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""

# Start Modal Armor API in background
Write-Host "1. Starting Modal Armor API on port 8000..." -ForegroundColor Cyan
$api_job = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    .\.venv\Scripts\Activate.ps1
    python -m uvicorn src.modal_armor.api.server:app --host 0.0.0.0 --port 8000
}
Write-Host "   Modal Armor API started (Job ID: $($api_job.Id))" -ForegroundColor Green

# Wait for API to start
Write-Host "   Waiting for API to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Start Streamlit chatbot
Write-Host ""
Write-Host "2. Starting Streamlit Chatbot..." -ForegroundColor Cyan
Write-Host ""
Write-Host "================================================" -ForegroundColor Magenta
Write-Host "  Open http://localhost:8501 in your browser" -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Magenta
Write-Host ""

# Run Streamlit
streamlit run chatbot/app.py --server.port 8501

# Cleanup
Write-Host ""
Write-Host "Shutting down services..." -ForegroundColor Yellow
Stop-Job $api_job
Remove-Job $api_job
Write-Host "Done!" -ForegroundColor Green
