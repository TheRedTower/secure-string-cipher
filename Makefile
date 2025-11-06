.PHONY: help format lint test test-fast test-watch test-unit test-integration test-security test-quick test-failed test-cov clean install ci

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install package and dev dependencies
	pip install -e ".[dev]"

format:  ## Auto-format code with Ruff
	@echo "✨ Formatting code with Ruff..."
	ruff format src tests
	ruff check --fix src tests
	@echo "✅ Formatting complete!"

lint:  ## Run all linting checks (Ruff format check, Ruff lint, mypy)
	@echo "🔍 Checking code format..."
	ruff format --check src tests
	@echo "� Checking code quality..."
	ruff check src tests
	@echo "🔬 Running mypy type checks..."
	mypy src tests
	@echo "✅ All linting checks passed!"

test:  ## Run tests with pytest
	@echo "🧪 Running tests..."
	pytest tests/ -v

test-fast:  ## Run tests in parallel (3-4x faster)
	@echo "🚀 Running tests in parallel..."
	pytest -n auto --dist loadfile -p no:benchmark

test-watch:  ## Run tests in watch mode (auto-rerun on changes)
	@echo "👀 Watching for changes..."
	pytest-watch

test-unit:  ## Run only unit tests
	@echo "🧪 Running unit tests..."
	pytest -m unit -v

test-integration:  ## Run only integration tests
	@echo "🔗 Running integration tests..."
	pytest -m integration -v

test-security:  ## Run only security tests
	@echo "🔒 Running security tests..."
	pytest -m security -v

test-quick:  ## Run tests excluding slow ones
	@echo "⚡ Running quick tests..."
	pytest -m "not slow" -v

test-failed:  ## Re-run only failed tests
	@echo "🔄 Re-running failed tests..."
	pytest --lf -v

test-cov:  ## Run tests with coverage report
	@echo "🧪 Running tests with coverage..."
	pytest tests/ --cov=secure_string_cipher --cov-report=term-missing --cov-report=html

clean:  ## Clean up temporary files
	@echo "🧹 Cleaning up..."
	rm -rf .pytest_cache .mypy_cache .ruff_cache __pycache__
	rm -rf htmlcov .coverage coverage.xml coverage.json
	rm -rf dist build *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "✨ Clean!"

ci:  ## Run all CI checks locally (format, lint, test)
	@echo "🚀 Running full CI pipeline locally..."
	@make format
	@make lint
	@make test
	@echo "✅ All CI checks passed! Ready to push."
