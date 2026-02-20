# Multi-stage build for security and size
FROM python:3.11-slim-bookworm AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    cargo \
    python3-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies in builder stage
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt && \
     rm -rf /root/.cache/pip


# Final stage with minimal image
FROM python:3.11-slim-bookworm

# Update system packages immediately to fix vulnerabilities
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && \
    useradd -r -g appuser -u 1000 appuser && \
    mkdir -p /app && \
    chown -R appuser:appuser /app

WORKDIR /app

# Copy only necessary files from builder
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appuser app.py .

# Switch to non-root user
USER appuser

# Add user's local bin to PATH
ENV PATH=/home/appuser/.local/bin:$PATH

# Only expose necessary port
EXPOSE 5000

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health')" || exit 1

# Use production WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]