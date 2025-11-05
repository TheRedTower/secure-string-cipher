# Dockerfile for string-cipher

FROM python:3.11-slim

WORKDIR /app

# Copy project files
COPY pyproject.toml README.md LICENSE string_cipher.py /app/

# Install runtime dependencies
RUN pip install --no-cache-dir .

ENTRYPOINT ["string-cipher"]
CMD []
