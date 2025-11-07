FROM python:3.14-alpine AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust

COPY pyproject.toml README.md LICENSE ./

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=cache,target=/root/.cargo/registry \
    pip install --upgrade pip \
    && pip install build cryptography wcwidth pyperclip

COPY src/ ./src/

RUN --mount=type=cache,target=/root/.cache/pip \
    python -m build --wheel --outdir /build/wheels

FROM python:3.14-alpine

RUN --mount=type=cache,target=/var/cache/apk \
    adduser -D -u 1000 -s /bin/sh cipheruser \
    && mkdir -p /data /home/cipheruser/.secure-cipher /home/cipheruser/.secure-cipher/backups \
    && chown -R cipheruser:cipheruser /data /home/cipheruser/.secure-cipher \
    && chmod 700 /home/cipheruser/.secure-cipher /home/cipheruser/.secure-cipher/backups \
    && apk add --no-cache libffi openssl

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/cipheruser/.local/bin:$PATH" \
    CIPHER_VAULT_PATH="/home/cipheruser/.secure-cipher/passphrase_vault.enc"

COPY --from=builder --chown=cipheruser:cipheruser /build/wheels /tmp/wheels

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-compile /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels \
    && find /usr/local -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true \
    && find /usr/local -type f -name "*.pyc" -delete

USER cipheruser
WORKDIR /data

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
