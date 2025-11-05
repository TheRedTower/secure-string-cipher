# Data Directory

This directory is used for Docker volume mounting. Place files here that you want to encrypt/decrypt using the Docker container.

## Usage with Docker Compose

```bash
# Place your files in this directory
cp /path/to/secret.txt data/

# Run the container
docker-compose run --rm cipher

# Select option 3 (Encrypt file)
# Enter path: /data/secret.txt
```

The encrypted files will appear in this directory with `.enc` extension.
