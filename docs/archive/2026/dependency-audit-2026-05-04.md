# Dependency audit report — historical snapshot

> [!IMPORTANT]
> This report captures the dependency graph and scanner output for v1.0.33 on
> May 4, 2026. It is not a current vulnerability assessment. Use the locked
> environment and current CI security checks for present-day results.

**Date:** 2026-05-04
**Project:** secure-string-cipher v1.0.33
**Audit Tool:** pip-audit v2.9.0

## Executive Summary

**Total Vulnerabilities Found:** 8 CVEs across 6 packages
**Direct Dependencies Affected:** 0
**Development Dependencies Affected:** 6
**Critical/High Severity:** 0
**Medium Severity:** 8

**Status:** ✅ **ACCEPTABLE FOR RELEASE**

All vulnerabilities are in development/testing tooling (pytest, pip-audit, detect-secrets, pre-commit, virtualenv) or their transitive dependencies. **No vulnerabilities exist in production runtime dependencies** (cryptography, argon2-cffi, pynacl, urllib3, pyperclip, wcwidth).

---

## Vulnerability Details

### 1. filelock 3.20.0 (Transitive via virtualenv, pre-commit)

**CVE:** GHSA-w853-jp5j-5j7f, GHSA-qmgc-5h2g-mvrw
**Severity:** Medium
**Fix Version:** 3.20.1 (CVE-1), 3.20.3 (CVE-2)
**Type:** TOCTOU race condition in symlink handling
**Impact:** Local attackers can corrupt arbitrary files through symlink attacks during lock file operations. Requires local filesystem access and ability to create symlinks.

**Affected Context:**

- Development tooling (virtualenv, pre-commit)
- NOT used by production application code
- Attack surface limited to developer machines during build/test

**Risk Assessment:** 🟢 **LOW** - Does not affect runtime. Development environment risk only.

---

### 2. pip 25.3 (Transitive via pip-audit)

**CVE:** GHSA-6vgw-5pg2-w6jp, GHSA-58qw-9mgm-455v
**Severity:** Medium
**Fix Version:** 26.0
**Type:** Path traversal in wheel extraction; ZIP/tar file confusion
**Impact:** Malicious wheels could extract files outside installation directory (limited to installation prefix). Second issue causes incorrect file installation.

**Affected Context:**

- Used only by pip-audit (vulnerability scanner)
- NOT used by production application
- Attack surface limited to dependency scanning operations

**Risk Assessment:** 🟢 **LOW** - Tooling-only impact. No production exposure.

---

### 3. pygments 2.19.2 (Transitive via pytest, pip-audit)

**CVE:** GHSA-5239-wwwm-4pmq
**Severity:** Medium
**Fix Version:** 2.20.0
**Type:** Inefficient regular expression complexity (ReDoS) in AdlLexer
**Impact:** Local attackers can cause denial of service via CPU exhaustion.

**Affected Context:**

- Used by pytest (test runner) and pip-audit (reporting)
- NOT used in production code paths
- Requires attacker to control input to lexer (test output, dependency reports)

**Risk Assessment:** 🟢 **LOW** - Development/testing only. No production exposure.

---

### 4. pytest 8.4.2 (Dev dependency)

**CVE:** GHSA-6w46-j5rx-g56g
**Severity:** Medium
**Fix Version:** 9.0.3
**Type:** Predictable `/tmp/pytest-of-{user}` directory names
**Impact:** Local users can cause denial of service or potentially gain privileges during test execution.

**Affected Context:**

- Test runner only
- NOT used in production
- Requires local access to system running tests

**Risk Assessment:** 🟢 **LOW** - Test environment only. No production impact.

---

### 5. requests 2.32.5 (Transitive via detect-secrets, pip-audit)

**CVE:** GHSA-gc5v-m9x4-r6x2
**Severity:** Medium
**Fix Version:** 2.33.0
**Type:** Predictable temp file names in `extract_zipped_paths()`
**Impact:** Local attackers can pre-create malicious files loaded instead of legitimate ones.

**Affected Context:**

- Used by detect-secrets (secret scanning) and pip-audit (dependency scanning)
- NOT used by production application code
- Standard usage of Requests is NOT affected - only `extract_zipped_paths()`

**Risk Assessment:** 🟢 **LOW** - Tooling-only impact. No production exposure.

---

### 6. virtualenv 20.35.4 (Transitive via pre-commit)

**CVE:** GHSA-597g-3phw-6986
**Severity:** Medium
**Fix Version:** 20.36.1
**Type:** TOCTOU race condition in directory creation
**Impact:** Local attackers can redirect virtualenv operations to attacker-controlled locations (cache poisoning, info disclosure).

**Affected Context:**

- Used by pre-commit hook framework only
- NOT used in production
- Requires local filesystem access

**Risk Assessment:** 🟢 **LOW** - Pre-commit tooling only. No production impact.

---

## Production Dependencies - CLEAN ✅

The following production runtime dependencies have **NO known vulnerabilities**:

| Package | Version | Purpose |
| --------- | --------- | ---------- |
| cryptography | 46.0.7 | Core AES-256-GCM encryption, key derivation |
| argon2-cffi | 25.1.0 | Memory-hard password hashing (Argon2id) |
| pynacl | 1.6.2 | Secure memory, constant-time operations |
| urllib3 | 2.6.3 | HTTP client (if used) |
| pyperclip | 1.11.0 | Clipboard operations |
| wcwidth | 0.2.14 | Terminal width calculation |

**These are the security-critical dependencies** that handle encryption, key derivation, and secure memory. All are up-to-date and vulnerability-free.

---

## Risk Acceptance Rationale

### 1. No Production Impact

All 8 vulnerabilities exist in:

- Development tools (pytest, pre-commit, virtualenv)
- Security scanning tools (pip-audit, detect-secrets)
- Their transitive dependencies

**Zero vulnerabilities in production runtime dependencies.** The application's cryptographic stack (cryptography, argon2-cffi, pynacl) is completely clean.

### 2. Attack Surface

Vulnerabilities require:

- Local filesystem access to the development/build environment
- Ability to create symlinks or control temp directories
- Execution during development/testing phases

**Not exploitable in production deployment** where these tools are not present.

### 3. Severity Profile

All vulnerabilities are **Medium severity** (CVSS ~5.6). None are Critical or High.
Primary impact: Denial of service during development/testing.
No remote code execution or privilege escalation in production context.

### 4. Development vs Production

- **Development environment:** Acceptable risk (ephemeral, controlled)
- **CI/CD pipeline:** Acceptable risk (isolated, ephemeral runners)
- **Production deployment:** **ZERO exposure** (no vulnerable packages installed)

### 5. Mitigation Options (if needed)

- Development dependencies can be updated independently of production
- Virtual environments isolate development from production
- Docker builds use multi-stage builds - dev deps not in final image

---

## Recommendations

### Immediate (Pre-Release)

- ✅ **PROCEED WITH RELEASE** - No blocking vulnerabilities
- ✅ Production dependencies are clean and up-to-date
- ✅ Security-critical crypto stack is fully patched

### Short-Term (Next Sprint)

- Update dev dependencies when convenient (pytest 9.x, filelock 3.20.3)
- Not required for security - only for hygiene

### Long-Term

- Implement automated dependency scanning in CI
- Set up Dependabot or similar for automated PRs
- Regular quarterly dependency reviews

---

## Verification Commands

```bash
# Verify production deps are clean
uv run --locked pip-audit --production

# Full scan (includes dev)
uv run --locked pip-audit

# Check specific package
uv run --locked pip-audit -r <package>
```

## Conclusion

**The application is SAFE TO RELEASE.** All vulnerabilities are confined to development and testing tooling with no impact on production runtime. The security-critical cryptographic dependencies (cryptography, argon2-cffi, pynacl) are fully patched and vulnerability-free.

**Risk Level:** 🟢 **LOW**
**Release Status:** ✅ **APPROVED**
