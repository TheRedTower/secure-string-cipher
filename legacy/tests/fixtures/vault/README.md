# Synthetic Current-Format Vault Fixture

`current-vault.enc.b64` preserves the exact no-final-newline bytes emitted by
the released writer in base64 transport form. Its decoded contents contain only
the synthetic entries and public test-only credential recorded in
`manifest.json`. It was generated with the released v1.3.0 `PassphraseVault`
writer in a disposable detached worktree using that release's locked
dependencies. The worktree was removed after provenance and hashes were
recorded.

The current vault format has a magic header but no explicit version field,
encoded-size bound, or entry-count bound. This fixture is compatibility
evidence, not user data and not a credential suitable for real use.

A future versioned vault format should add authenticated total-size and
entry-count fields so readers can enforce limits without rejecting legacy
vaults. Until then, transactional import applies an external bounded-input
limit while active loading remains compatible with unbounded released vaults.
