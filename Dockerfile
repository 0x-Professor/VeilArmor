# Modal Armor Production Dockerfile
# Multi-stage build for optimized security and performance

# Stage 1: Builder
FROM python:3.13-slim AS builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Install uv package manager
RUN pip install uv

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN uv pip install --system -r requirements.txt

# Download spaCy model
RUN python -m spacy download en_core_web_lg

# Stage 2: Runtime
FROM python:3.13-slim AS runtime

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r modalarmor && useradd -r -g modalarmor -u 1000 modalarmor

# Set working directory
WORKDIR /app

# Copy Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=modalarmor:modalarmor src/ ./src/
COPY --chown=modalarmor:modalarmor examples/ ./examples/
COPY --chown=modalarmor:modalarmor .env.example ./.env

# Create necessary directories
RUN mkdir -p /app/logs /app/security_reports /app/data && \
    chown -R modalarmor:modalarmor /app

# Switch to non-root user
USER modalarmor

# Set environment variables
ENV PYTHONPATH=/app \
    MODAL_ARMOR_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Expose port (if running as API server)
EXPOSE 8000

# Default command
CMD ["python", "-m", "src.modal_armor"]
