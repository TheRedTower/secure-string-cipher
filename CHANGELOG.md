# Changelog

## Unreleased

- Make CLI testable: `main()` now accepts optional `in_stream` and `out_stream` file-like parameters so tests can pass StringIO objects and reliably capture I/O without interfering with pytest output capture.
- Route all CLI input/output through provided streams and avoid writing directly to `sys.__stdout__`.
- Improve error messages: wrap invalid base64 errors during text decryption into a generic "Text decryption failed" CryptoError to align with tests.
- Tidy: removed unused helper and imports in `src/secure_string_cipher/cli.py`.

