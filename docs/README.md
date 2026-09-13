# Documentation

Welcome to the secure-string-cipher documentation.

## Quick Links

### API Reference

- [API.md](API.md) — Complete programmatic API documentation for all public functions and classes

### Keychain & Storage

- [Keychain Backend](KEYCHAIN.md) — OS keychain integration guide (macOS/Windows/Linux)

### Migration

- [V1 to V2 Migration Guide](MIGRATION.md) — Moving from passphrase-only V1 usage to V2 managed keys and combined grants

### Security

- [Security Policy](../.github/SECURITY.md) — Supported versions, vulnerability reporting, and security policy
- [Cryptographic Design](../.github/CRYPTOGRAPHY.md) — Detailed cryptographic design document for security auditors
- [Audit Checklist](../.github/AUDIT_CHECKLIST.md) — Current review checklist for security auditors
- [Threat Model](THREAT_MODEL.md) — What SSC does and does not protect against
- [V2 Secret Lifetime Inventory](V2_SECRET_LIFETIME_INVENTORY.md) — Where every v2/vault secret comes from, how long it lives, and whether it's wiped
- [SSC2 Protocol Specification](SSC2_PROTOCOL_SPECIFICATION.md) — Language-independent wire format for the `.ssc` v2 container, `.ssckey` files, and their cryptographic construction
- [SSC V2 Refined Implementation Specification](SSC_V2_REFINED_IMPLEMENTATION_SPEC.md) — The implementation-planning source document behind the protocol spec above: decision rationale, resource-policy table, and the staged-PR history that built it
- [V2 Post-Implementation Hardening Review](V2_POST_IMPLEMENTATION_HARDENING_REVIEW.md) — Finding matrix and PR log from the post-v2 hardening pass

### Development

- [Developer Guide](../DEVELOPER.md) — Development workflow, tooling, and CI/CD
- [Contributing](../CONTRIBUTING.md) — Contribution and sole-maintainer review workflow
- [Release Guide](../RELEASE.md) — Reusable preparation, validation, and publication checklist

### Project Info

- [Changelog](../CHANGELOG.md) — Release history and version notes
- [License](../LICENSE) — MIT License

### Historical Evidence

- [Documentation Archive](archive/README.md) — Dated implementation plans, audit snapshots, and acceptance records
- [V2 Managed Keys Architecture](V2_MANAGED_KEYS_ARCHITECTURE.md) — The original design draft; self-marked superseded by the refined spec above, kept for design-rationale context, not as an implementation reference
- [V2 Antigravity Implementation Guide](V2_ANTIGRAVITY_IMPLEMENTATION_GUIDE.md) — Process instructions for the agent that implemented v2 against the architecture draft above; historical, not a current procedure
- [Archived: Fast-Track Implementation](FAST_TRACK_IMPLEMENTATION.md), [Archived: Stabilization Tranche 2](SSC_STABILIZATION_TRANCHE_2.md) — Redirect stubs kept at their original paths for old links; the dated records they point to live under the documentation archive above

Historical documents preserve their original dates, commits, counts, and
pending work. They must not be treated as current security or release status.

## Getting Help

- **Bug reports**: Use the [GitHub issue tracker](https://github.com/TheRedTower/secure-string-cipher/issues)
- **Security issues**: Report privately via [GitHub Security Advisories](https://github.com/TheRedTower/secure-string-cipher/security/advisories) or email <security@avondenecloud.uk>
- **Questions and support**: Open a non-security [GitHub issue](https://github.com/TheRedTower/secure-string-cipher/issues/new/choose)

This is a volunteer, sole-maintainer project. Support and response times are
best effort.
