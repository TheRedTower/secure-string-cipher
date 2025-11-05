"""
Shared test configuration and fixtures
"""
import os
import tempfile
import pytest

@pytest.fixture(scope="session")
def test_env():
    """Set up test environment variables."""
    old_env = {}
    
    # Store old values
    for key in ['NO_COLOR', 'COLORFGBG']:
        old_env[key] = os.environ.get(key)
    
    # Set test values
    os.environ['NO_COLOR'] = '1'  # Disable colors in tests
    
    yield
    
    # Restore old values
    for key, value in old_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

@pytest.fixture
def large_test_file():
    """Create a large temporary test file."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        # Write 1MB of random-like but reproducible data
        for i in range(1024):  # 1024 * 1024 = 1MB
            tf.write(bytes([i % 256] * 1024))
        path = tf.name
    
    yield path
    
    try:
        os.unlink(path)
    except OSError:
        pass