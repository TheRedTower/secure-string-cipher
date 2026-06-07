.PHONY: help format lint security-guard test test-fast test-watch test-unit test-integration test-security test-quick test-failed test-cov clean install ci docker-build docker-build-fast docker-build-ultra docker-run docker-test docker-clean docker-size

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install package and dev dependencies
	uv sync --extra dev --locked

format:  ## Auto-format code with Ruff
	@echo "✨ Formatting code with Ruff..."
	uv run --locked ruff format src tests tools
	uv run --locked ruff check --fix src tests tools
	@echo "✅ Formatting complete!"

lint:  ## Run all linting checks (Ruff format check, Ruff lint, mypy)
	@echo "🔍 Checking code format..."
	uv run --locked ruff format --check src tests tools
	@echo "� Checking code quality..."
	uv run --locked ruff check src tests tools
	@echo "🔬 Running mypy type checks on production code..."
	uv run --locked mypy src
	@make security-guard
	@echo "✅ All linting checks passed!"

security-guard:  ## Check that CLI/audit paths do not output credential material
	@echo "🔒 Checking for sensitive CLI/audit output..."
	uv run --locked python tools/check_sensitive_output.py

lint-tests:  ## Run the gradual non-blocking mypy check for tests
	@echo "🔬 Running mypy type checks on tests..."
	uv run --locked mypy tests

test:  ## Run tests with pytest
	@echo "🧪 Running tests..."
	uv run --locked pytest tests/ -v

test-fast:  ## Run tests in parallel (3-4x faster)
	@echo "🚀 Running tests in parallel..."
	uv run --locked pytest -n auto --dist loadfile

test-watch:  ## Run tests in watch mode (auto-rerun on changes)
	@echo "👀 Watching for changes..."
	uv run --locked pytest-watch

test-unit:  ## Run only unit tests
	@echo "🧪 Running unit tests..."
	uv run --locked pytest tests/unit -v

test-integration:  ## Run only integration tests
	@echo "🔗 Running integration tests..."
	uv run --locked pytest tests/integration -v

test-security:  ## Run only security tests
	@echo "🔒 Running security tests..."
	uv run --locked pytest tests/security tests/unit/test_kdf.py tests/security/test_key_commitment.py -v

test-quick:  ## Run fast tests only (~10s vs ~80s) - skips KDF/fuzz/perf
	@echo "⚡ Running quick tests (no KDF-heavy tests)..."
	uv run --locked pytest tests/unit/ tests/integration/ -q --ignore=tests/unit/test_kdf.py --ignore=tests/unit/test_core_extended.py --ignore=tests/unit/test_passphrase_manager_extended.py --ignore=tests/integration/test_passphrase_manager.py --ignore=tests/integration/test_cli_workflows.py -x

test-slow:  ## Run slow tests only (KDF, fuzz, performance)
	@echo "🐢 Running slow tests (KDF, fuzz, performance)..."
	uv run --locked pytest tests/unit/test_kdf.py tests/fuzz/ tests/performance/ -v

test-failed:  ## Re-run only failed tests
	@echo "🔄 Re-running failed tests..."
	uv run --locked pytest --lf -v

test-cov:  ## Run tests with coverage report
	@echo "🧪 Running tests with coverage..."
	uv run --locked pytest tests/ --cov=secure_string_cipher --cov-report=term-missing --cov-report=html

clean:  ## Clean up temporary files and caches
	@echo "🧹 Cleaning up..."
	rm -rf .pytest_cache .mypy_cache .ruff_cache __pycache__
	find . -type d -name __pycache__ -not -path "./.venv/*" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -not -path "./.venv/*" -delete
	rm -rf htmlcov .coverage coverage.xml coverage.json
	rm -rf dist build *.egg-info
	rm -rf .benchmarks
	rm -f *.enc *.dec .write_test
	@echo "✨ Clean!"

ci:  ## Run all CI checks locally (lint, format, test)
	@echo "🚀 Running full CI pipeline locally..."
	@make lint
	@make format
	@make test
	@echo "✅ All CI checks passed! Ready to push."

docker-build:  ## Build Docker image with cache
	@echo "🐳 Building Docker image..."
	DOCKER_BUILDKIT=1 docker build -t secure-string-cipher:latest .

docker-build-fast:  ## Build Docker image (optimized)
	@echo "⚡ Building Docker image (fast mode)..."
	DOCKER_BUILDKIT=1 docker build --build-arg BUILDKIT_INLINE_CACHE=1 -t secure-string-cipher:latest .

docker-build-ultra:  ## Build Docker image (maximum speed)
	@echo "🚀 Building Docker image (ultra mode)..."
	DOCKER_BUILDKIT=1 docker build \
		--build-arg BUILDKIT_INLINE_CACHE=1 \
		--cache-from secure-string-cipher:latest \
		--build-arg BUILDKIT_PROGRESS=plain \
		-t secure-string-cipher:latest .

docker-run:  ## Run Docker container interactively
	@echo "🏃 Running Docker container..."
	docker run -it --rm \
		-v $(PWD)/data:/data \
		-v $(HOME)/.secure-cipher-docker:/home/cipheruser/.secure-cipher \
		secure-string-cipher:latest

docker-test:  ## Build and test Docker image
	@echo "🧪 Building and testing Docker image..."
	@make docker-build
	docker run --rm secure-string-cipher:latest --help
	@echo "✅ Docker test passed!"

docker-size:  ## Show Docker image size details
	@echo "📊 Docker image size analysis:"
	@docker images secure-string-cipher:latest --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
	@echo ""
	@echo "Layer breakdown:"
	@docker history secure-string-cipher:latest --human --no-trunc | head -15

docker-clean:  ## Remove Docker images and cache
	@echo "🧹 Cleaning Docker artifacts..."
	docker rmi secure-string-cipher:latest 2>/dev/null || true
	docker builder prune -f
	@echo "✨ Clean!"
