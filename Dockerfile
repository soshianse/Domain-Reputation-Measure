# Multi-stage Dockerfile for Domain ASN Mapper
# Optimized for production deployment with minimal image size

# Stage 1: Builder
FROM python:3.11-slim as builder

LABEL maintainer="Domain ASN Mapper Team"
LABEL description="Multi-stage build for Domain ASN Mapper"

# Set working directory
WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files
COPY pyproject.toml ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -e ".[all]"

# Stage 2: Runtime
FROM python:3.11-slim

LABEL maintainer="Domain ASN Mapper Team"
LABEL version="2.0.0"
LABEL description="Domain ASN Mapper - Map domains to ASN infrastructure"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    DOMAIN_ASN_MAPPER_HOME=/app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=appuser:appuser ../../Downloads/Domain-Reputation-Measure .

# Create necessary directories with proper permissions
RUN mkdir -p /app/data /app/logs /app/visualizations /app/exports && \
    chown -R appuser:appuser /app

# Download default MRT file if not exists (lightweight initial setup)
RUN mkdir -p /app/data/mrt

# Switch to non-root user
USER appuser

# Expose ports
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command (can be overridden)
CMD ["python3", "main.py", "web", "--host", "0.0.0.0", "--port", "5000"]
