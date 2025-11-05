# Multi-stage Dockerfile for secure-string-cipher
# Optimized for security, minimal size, and ease of use

# Build stage
FROM python:3.14-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first for better layer caching
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Build the package
RUN pip install --no-cache-dir build && \
    python -m build && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels .

# Runtime stage
FROM python:3.14-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 -s /bin/bash cipheruser && \
    mkdir -p /data /home/cipheruser/.secure-cipher && \
    chown -R cipheruser:cipheruser /data /home/cipheruser/.secure-cipher

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/cipheruser/.local/bin:$PATH"

# Copy wheels from builder
COPY --from=builder /build/wheels /tmp/wheels
COPY --from=builder /build/dist/*.whl /tmp/

# Install the package
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/wheels /tmp/*.whl

# Switch to non-root user
USER cipheruser
WORKDIR /data

# Set the vault location to a persistent volume
ENV CIPHER_VAULT_PATH="/home/cipheruser/.secure-cipher/passphrase_vault.enc"

# Default entrypoint
ENTRYPOINT ["cipher-start"]
CMD []

# Metadata
LABEL maintainer="TheRedTower <security@avondenecloud.uk>" \
      description="Secure AES-256-GCM encryption utility with passphrase management" \
      version="1.0.4" \
      org.opencontainers.image.source="https://github.com/TheRedTower/secure-string-cipher" \
      org.opencontainers.image.licenses="MIT"
