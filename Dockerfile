
# Multi-stage Dockerfile for secure-string-cipher
# Optimized for security, minimal size, and fast builds

FROM python:3.14-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies in a separate layer for better caching
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust

# Copy only dependency specifications first (better cache utilization)
COPY pyproject.toml README.md LICENSE ./

# Pre-install dependencies to cache this expensive layer
# This layer only rebuilds when pyproject.toml changes
RUN pip install --no-cache-dir --upgrade "pip>=25.3" && \
    pip install --no-cache-dir build && \
    pip install --no-cache-dir \
        cryptography \
        wcwidth \
        pyperclip

# Copy source code (changes frequently, so kept separate)
COPY src/ ./src/

# Build the wheel (quick since dependencies already installed)
RUN python -m build && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels .

FROM python:3.14-alpine

RUN adduser -D -u 1000 -s /bin/sh cipheruser && \
    mkdir -p /data /home/cipheruser/.secure-cipher /home/cipheruser/.secure-cipher/backups && \
    chown -R cipheruser:cipheruser /data /home/cipheruser/.secure-cipher && \
    chmod 700 /home/cipheruser/.secure-cipher /home/cipheruser/.secure-cipher/backups

RUN apk add --no-cache \
    libffi \
    openssl

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/cipheruser/.local/bin:$PATH"

COPY --from=builder --chown=cipheruser:cipheruser /build/wheels /tmp/wheels
COPY --from=builder --chown=cipheruser:cipheruser /build/dist/*.whl /tmp/

RUN pip install --no-cache-dir --upgrade "pip>=25.3" && \
    pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/wheels /tmp/*.whl /root/.cache

USER cipheruser
WORKDIR /data

ENV CIPHER_VAULT_PATH="/home/cipheruser/.secure-cipher/passphrase_vault.enc"

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=1 \
    CMD python -c "import secure_string_cipher; print('healthy')" || exit 1

ENTRYPOINT ["cipher-start"]
CMD []

LABEL maintainer="TheRedTower <security@avondenecloud.uk>" \
      description="Secure AES-256-GCM encryption utility with passphrase management" \
      version="1.0.13" \
      org.opencontainers.image.title="secure-string-cipher" \
      org.opencontainers.image.description="Secure AES-256-GCM encryption utility with HMAC integrity and automatic backups" \
      org.opencontainers.image.url="https://github.com/TheRedTower/secure-string-cipher" \
      org.opencontainers.image.source="https://github.com/TheRedTower/secure-string-cipher" \
      org.opencontainers.image.version="1.0.13" \
      org.opencontainers.image.vendor="TheRedTower" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="TheRedTower <security@avondenecloud.uk>" \
      org.opencontainers.image.documentation="https://github.com/TheRedTower/secure-string-cipher/blob/main/README.md" \
      org.opencontainers.image.base.name="python:3.14-alpine"
