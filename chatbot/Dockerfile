# Veil Armor Chatbot Dockerfile
# Supports both secure and unsecure modes via environment variable

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create startup script
RUN echo '#!/bin/bash\n\
if [ "$CHATBOT_MODE" = "unsecure" ]; then\n\
    echo "Starting UNSECURE chatbot (no security checks)..."\n\
    streamlit run app_unsecure.py --server.port=8501 --server.address=0.0.0.0\n\
else\n\
    echo "Starting SECURE chatbot with Veil Armor protection..."\n\
    streamlit run app_secure.py --server.port=8501 --server.address=0.0.0.0\n\
fi' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run startup script
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
