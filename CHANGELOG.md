# Changelog

## 1.0.1 (2025-11-05)

- **Command rename**: CLI command changed from `secure-string-cipher` to `cipher-start` for easier invocation
- Updated README with correct command usage

## 1.0.0 (2025-11-05)

- CLI testability: `main()` accepts optional `in_stream` and `out_stream` file-like parameters so tests can pass StringIO objects and reliably capture I/O.
- CLI exit control: add `exit_on_completion` (default True). When False, `main()` returns 0/1 instead of calling `sys.exit()`. Tests use this to avoid catching `SystemExit`.
- Route all CLI I/O through provided streams; avoid writing to `sys.__stdout__`.
- Error message consistency: wrap invalid base64 during text decryption into `CryptoError("Text decryption failed")`.
- Tidy: removed unused helper and imports in `src/secure_string_cipher/cli.py`. Enabled previously skipped CLI tests.

