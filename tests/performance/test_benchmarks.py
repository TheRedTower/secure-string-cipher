"""
Performance benchmark tests for secure-string-cipher.

These tests measure and document the performance characteristics
of cryptographic operations for optimization and regression detection.

Run with: pytest tests/performance/ -v --benchmark-only
         pytest tests/performance/ -v --benchmark-save=baseline
"""

import os
import time
from pathlib import Path
from statistics import median

import pytest

from secure_string_cipher.config import SALT_SIZE
from secure_string_cipher.core import (
    compute_key_commitment,
    decrypt_file,
    decrypt_text,
    derive_key,
    encrypt_file,
    encrypt_text,
    verify_key_commitment,
)
from secure_string_cipher.security import sanitize_filename
from secure_string_cipher.timing_safe import constant_time_compare

# =============================================================================
# Benchmark Fixtures
# =============================================================================


@pytest.fixture
def sample_passphrase() -> str:
    """Standard passphrase for benchmarks."""
    return "BenchmarkPass123!@#"


@pytest.fixture
def sample_salt() -> bytes:
    """Standard salt for benchmarks."""
    return os.urandom(SALT_SIZE)


@pytest.fixture
def sample_key(sample_passphrase: str, sample_salt: bytes) -> bytes:
    """Pre-derived key for benchmarks that don't measure KDF."""
    return derive_key(sample_passphrase, sample_salt)


@pytest.fixture
def temp_file(tmp_path: Path) -> Path:
    """Create a temporary file for file encryption benchmarks."""
    file_path = tmp_path / "benchmark_file.txt"
    file_path.write_text("A" * 1024 * 100)  # 100 KB
    return file_path


@pytest.fixture
def large_temp_file(tmp_path: Path) -> Path:
    """Create a larger temporary file for throughput benchmarks."""
    file_path = tmp_path / "large_benchmark_file.bin"
    file_path.write_bytes(os.urandom(1024 * 1024))  # 1 MB
    return file_path


# =============================================================================
# Key Derivation Benchmarks
# =============================================================================


class TestKeyDerivationBenchmarks:
    """Benchmarks for Argon2id key derivation."""

    @pytest.mark.benchmark
    def test_derive_key_latency(self, sample_passphrase: str, sample_salt: bytes):
        """Benchmark: Single key derivation latency."""
        iterations = 3
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            derive_key(sample_passphrase, sample_salt)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        avg_time = sum(times) / len(times)

        # Document expected performance
        # Argon2id should take meaningful time but fast machines may be quicker
        # Lower bound is 0.01s (10ms) - anything faster suggests wrong parameters
        assert avg_time > 0.01, (
            "Key derivation suspiciously fast - check Argon2id parameters"
        )
        assert avg_time < 5.0, "Key derivation too slow - may impact UX"

        print("\n📊 Key Derivation Benchmark:")
        print(f"   Average: {avg_time * 1000:.1f} ms")
        print(f"   Min: {min(times) * 1000:.1f} ms")
        print(f"   Max: {max(times) * 1000:.1f} ms")

    @pytest.mark.benchmark
    def test_derive_key_memory_cost_impact(self, sample_passphrase: str):
        """Document the impact of memory cost on derivation time."""
        salt = os.urandom(SALT_SIZE)

        start = time.perf_counter()
        derive_key(sample_passphrase, salt)
        elapsed = time.perf_counter() - start

        print("\n📊 Memory Cost Impact (64MB):")
        print(f"   Derivation time: {elapsed * 1000:.1f} ms")
        print("   Target range: 300-1000 ms")


# =============================================================================
# Text Encryption Benchmarks
# =============================================================================


class TestTextEncryptionBenchmarks:
    """Benchmarks for text encryption/decryption."""

    @pytest.mark.benchmark
    @pytest.mark.parametrize(
        "size_name,size",
        [
            ("small", 100),
            ("medium", 1000),
            ("large", 10000),
            ("xlarge", 100000),
        ],
    )
    def test_encrypt_text_by_size(
        self, size_name: str, size: int, sample_passphrase: str
    ):
        """Benchmark: Text encryption at various sizes."""
        plaintext = "A" * size

        start = time.perf_counter()
        ciphertext = encrypt_text(plaintext, sample_passphrase)
        encrypt_time = time.perf_counter() - start

        start = time.perf_counter()
        decrypt_text(ciphertext, sample_passphrase)
        decrypt_time = time.perf_counter() - start

        print(f"\n📊 Text Encryption ({size_name}, {size} chars):")
        print(f"   Encrypt: {encrypt_time * 1000:.1f} ms")
        print(f"   Decrypt: {decrypt_time * 1000:.1f} ms")
        print(f"   Total: {(encrypt_time + decrypt_time) * 1000:.1f} ms")

    @pytest.mark.benchmark
    def test_encrypt_text_throughput(self, sample_passphrase: str):
        """Benchmark: Text encryption throughput."""
        plaintext = "A" * 10000  # 10 KB
        iterations = 5

        total_bytes = 0
        start = time.perf_counter()

        for _ in range(iterations):
            ciphertext = encrypt_text(plaintext, sample_passphrase)
            decrypt_text(ciphertext, sample_passphrase)
            total_bytes += len(plaintext) * 2  # encrypt + decrypt

        elapsed = time.perf_counter() - start
        throughput_kbps = (total_bytes / 1024) / elapsed

        print("\n📊 Text Encryption Throughput:")
        print(f"   Throughput: {throughput_kbps:.1f} KB/s")
        print("   Note: Includes Argon2id overhead per operation")


# =============================================================================
# File Encryption Benchmarks
# =============================================================================


class TestFileEncryptionBenchmarks:
    """Benchmarks for file encryption/decryption."""

    @pytest.mark.benchmark
    def test_file_encryption_100kb(
        self, temp_file: Path, tmp_path: Path, sample_passphrase: str
    ):
        """Benchmark: 100 KB file encryption."""
        output_path = tmp_path / "encrypted.enc"
        decrypted_path = tmp_path / "decrypted.txt"

        start = time.perf_counter()
        encrypt_file(str(temp_file), str(output_path), sample_passphrase)
        encrypt_time = time.perf_counter() - start

        start = time.perf_counter()
        decrypt_file(str(output_path), str(decrypted_path), sample_passphrase)
        decrypt_time = time.perf_counter() - start

        file_size_kb = temp_file.stat().st_size / 1024

        print(f"\n📊 File Encryption ({file_size_kb:.0f} KB):")
        print(f"   Encrypt: {encrypt_time * 1000:.1f} ms")
        print(f"   Decrypt: {decrypt_time * 1000:.1f} ms")
        print(f"   Throughput: {file_size_kb / (encrypt_time + decrypt_time):.1f} KB/s")

    @pytest.mark.benchmark
    def test_file_encryption_1mb(
        self, large_temp_file: Path, tmp_path: Path, sample_passphrase: str
    ):
        """Benchmark: 1 MB file encryption."""
        output_path = tmp_path / "large_encrypted.enc"
        decrypted_path = tmp_path / "large_decrypted.bin"

        start = time.perf_counter()
        encrypt_file(str(large_temp_file), str(output_path), sample_passphrase)
        encrypt_time = time.perf_counter() - start

        start = time.perf_counter()
        decrypt_file(str(output_path), str(decrypted_path), sample_passphrase)
        decrypt_time = time.perf_counter() - start

        file_size_mb = large_temp_file.stat().st_size / (1024 * 1024)

        print(f"\n📊 File Encryption ({file_size_mb:.1f} MB):")
        print(f"   Encrypt: {encrypt_time * 1000:.1f} ms")
        print(f"   Decrypt: {decrypt_time * 1000:.1f} ms")
        print(f"   Throughput: {file_size_mb / (encrypt_time + decrypt_time):.2f} MB/s")


# =============================================================================
# Key Commitment Benchmarks
# =============================================================================


class TestKeyCommitmentBenchmarks:
    """Benchmarks for key commitment operations."""

    @pytest.mark.benchmark
    def test_key_commitment_compute(self, sample_key: bytes):
        """Benchmark: Key commitment computation."""
        iterations = 1000

        start = time.perf_counter()
        for _ in range(iterations):
            compute_key_commitment(sample_key)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / iterations) * 1_000_000

        print("\n📊 Key Commitment Computation:")
        print(f"   Average: {avg_us:.2f} µs")
        print(f"   Iterations: {iterations}")

        # Should be very fast (sub-millisecond)
        assert avg_us < 1000, "Key commitment too slow"

    @pytest.mark.benchmark
    def test_key_commitment_verify(self, sample_key: bytes):
        """Benchmark: Key commitment verification."""
        commitment = compute_key_commitment(sample_key)
        iterations = 1000

        start = time.perf_counter()
        for _ in range(iterations):
            verify_key_commitment(sample_key, commitment)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / iterations) * 1_000_000

        print("\n📊 Key Commitment Verification:")
        print(f"   Average: {avg_us:.2f} µs")
        print(f"   Iterations: {iterations}")


# =============================================================================
# Constant-Time Operation Benchmarks
# =============================================================================


class TestConstantTimeBenchmarks:
    """Benchmarks for constant-time operations."""

    @pytest.mark.benchmark
    def test_constant_time_compare_same_length(self):
        """Benchmark: Constant-time comparison with same-length strings."""
        a = "a" * 100
        b = "b" * 100
        iterations = 10000

        start = time.perf_counter()
        for _ in range(iterations):
            constant_time_compare(a, b)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / iterations) * 1_000_000

        print("\n📊 Constant-Time Compare (100 chars):")
        print(f"   Average: {avg_us:.2f} µs")

    @pytest.mark.benchmark
    def test_constant_time_compare_timing_consistency(self):
        """Verify timing doesn't leak information based on match position.

        Note: This test uses a high tolerance (5x) because CI runners have
        variable CPU scheduling that causes timing variance. The actual
        constant_time_compare uses hmac.compare_digest which is guaranteed
        constant-time at the C level.
        """
        base = b"A" * 100
        early_mismatch = b"B" + b"A" * 99
        late_mismatch = b"A" * 99 + b"B"
        iterations = 2000
        rounds = 9

        # Warm up caches and the interpreter before collecting samples.
        for _ in range(100):
            constant_time_compare(base, early_mismatch)
            constant_time_compare(base, late_mismatch)

        def measure(candidate: bytes) -> float:
            start = time.perf_counter()
            for _ in range(iterations):
                constant_time_compare(base, candidate)
            return time.perf_counter() - start

        early_samples: list[float] = []
        late_samples: list[float] = []
        for round_index in range(rounds):
            if round_index % 2 == 0:
                early_samples.append(measure(early_mismatch))
                late_samples.append(measure(late_mismatch))
            else:
                late_samples.append(measure(late_mismatch))
                early_samples.append(measure(early_mismatch))

        # Medians of interleaved samples are less sensitive to runner scheduling.
        early_time = median(early_samples)
        late_time = median(late_samples)
        ratio = max(early_time, late_time) / min(early_time, late_time)

        print("\n📊 Timing Consistency Check:")
        print(f"   Early mismatch: {early_time * 1000:.2f} ms")
        print(f"   Late mismatch: {late_time * 1000:.2f} ms")
        print(f"   Ratio: {ratio:.3f} (should be close to 1.0)")

        # High tolerance for CI - hmac.compare_digest is constant-time at C level
        # regardless of what Python-level timing measurements show
        assert ratio < 5.0, f"Timing variance extremely high: {ratio}"


# =============================================================================
# Input Validation Benchmarks
# =============================================================================


class TestInputValidationBenchmarks:
    """Benchmarks for input validation operations."""

    @pytest.mark.benchmark
    def test_sanitize_filename_speed(self):
        """Benchmark: Filename sanitization speed."""
        filenames = [
            "normal_file.txt",
            "../../../etc/passwd",
            "file with spaces.pdf",
            "unicode_文件名.doc",
            "a" * 255,
        ]
        iterations = 1000

        start = time.perf_counter()
        for _ in range(iterations):
            for filename in filenames:
                sanitize_filename(filename)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / (iterations * len(filenames))) * 1_000_000

        print("\n📊 Filename Sanitization:")
        print(f"   Average: {avg_us:.2f} µs per filename")


# =============================================================================
# Summary Report
# =============================================================================


class TestBenchmarkSummary:
    """Generate a summary of all benchmarks."""

    @pytest.mark.benchmark
    def test_generate_summary(self, sample_passphrase: str, tmp_path: Path):
        """Generate a performance summary report."""
        results = {}

        # Key derivation
        salt = os.urandom(SALT_SIZE)
        start = time.perf_counter()
        key = derive_key(sample_passphrase, salt)
        results["key_derivation_ms"] = (time.perf_counter() - start) * 1000

        # Text encryption (1 KB)
        plaintext = "A" * 1000
        start = time.perf_counter()
        ct = encrypt_text(plaintext, sample_passphrase)
        results["text_encrypt_1kb_ms"] = (time.perf_counter() - start) * 1000

        # Text decryption
        start = time.perf_counter()
        decrypt_text(ct, sample_passphrase)
        results["text_decrypt_1kb_ms"] = (time.perf_counter() - start) * 1000

        # Key commitment
        start = time.perf_counter()
        for _ in range(1000):
            compute_key_commitment(key)
        results["key_commitment_us"] = (time.perf_counter() - start) * 1000

        print("\n" + "=" * 60)
        print("📊 PERFORMANCE BENCHMARK SUMMARY")
        print("=" * 60)
        print(f"Key Derivation (Argon2id): {results['key_derivation_ms']:.1f} ms")
        print(f"Text Encrypt (1 KB):       {results['text_encrypt_1kb_ms']:.1f} ms")
        print(f"Text Decrypt (1 KB):       {results['text_decrypt_1kb_ms']:.1f} ms")
        print(f"Key Commitment (1000x):    {results['key_commitment_us']:.1f} ms")
        print("=" * 60)
        print("Note: Text operations include Argon2id key derivation")
        print("=" * 60)
