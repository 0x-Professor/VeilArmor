# Veil Armor Production Dockerfile
# Build with vigil-llm and all dependencies

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/app/.cache/huggingface \
    TRANSFORMERS_CACHE=/app/.cache/huggingface \
    NLTK_DATA=/usr/local/share/nltk_data

# Install runtime dependencies (including git for GitHub packages)
# Also install build dependencies for yara-python and openssl headers
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    gcc \
    g++ \
    libc-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security with home directory
RUN groupadd -r veilarmor && useradd -r -g veilarmor -u 1000 -m veilarmor

# Set working directory
WORKDIR /app

# Create cache directories with proper ownership BEFORE downloading models
RUN mkdir -p /app/.cache/huggingface /app/logs /app/data /home/veilarmor/nltk_data && \
    chown -R veilarmor:veilarmor /app /home/veilarmor

# Copy and install lightweight requirements
COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

# Download NLTK data required by vigil
RUN python -c "import nltk; nltk.download('vader_lexicon', download_dir='/usr/local/share/nltk_data')"

# Download spaCy model for Presidio PII detection (large model for best accuracy)
RUN python -m spacy download en_core_web_lg

# Pre-download Vigil prompt injection model to the app cache directory
RUN python -c "from transformers import AutoModelForSequenceClassification, AutoTokenizer; \
    AutoTokenizer.from_pretrained('protectai/deberta-v3-base-prompt-injection'); \
    AutoModelForSequenceClassification.from_pretrained('protectai/deberta-v3-base-prompt-injection')"

# Set ownership of downloaded models
RUN chown -R veilarmor:veilarmor /app/.cache

# Copy application code
COPY --chown=veilarmor:veilarmor src/ ./src/
COPY --chown=veilarmor:veilarmor .env.example ./.env

# Switch to non-root user
USER veilarmor

# Set environment variables
ENV PYTHONPATH=/app \
    VEIL_ARMOR_ENV=production

# Health check (increased start period for model loading)
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Default command - run API server with uvicorn
CMD ["python", "-m", "uvicorn", "src.veil_armor.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
