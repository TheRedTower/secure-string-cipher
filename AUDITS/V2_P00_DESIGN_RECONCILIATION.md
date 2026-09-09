# V2 Design Reconciliation (P00)

**Date:** 2026-09-09  
**Phase:** P00 Design Reconciliation  
**Authority:** SSC_V2_REFINED_IMPLEMENTATION_SPEC.md  

## 1. SHA Delta

- **Current `main` HEAD:** `e3d1d67a2676834fc9900cb36e1791c7ac15c626`
- **Current branch HEAD:** `284425832d0ff844c4aa0cd0bf69941446dc5482`
- **Spec snapshot baseline:** `e3d1d67a` for main, `112eebf9` for branch.
- **Delta:** The branch has been rebased and all local fixes squashed. The branch is exactly 1 commit ahead of main.

## 2. Gemini Refinement Dispositions

All 7 findings from spec §2 are **ACCEPTED**:
1. Canonical JSON structure bounds constraints (Accepted)
2. strict KDF profiling separation (Accepted)
3. keyfile serialization (Accepted)
4. atomic lock ordering (Accepted)
5. file chunking rules (Accepted)
6. outer metadata separation (Accepted)
7. protocol version byte length checks (Accepted)

## 3. Architecture Decisions (D01-D14)

All architecture decisions are **ACCEPTED**:
- **D01:** Keyfile `.ssckey` format — Strict text payload.
- **D02:** Protocol Identifier — `SSC2` magic prefix.
- **D03:** Cryptographic Primitives — AES-256-GCM, Argon2id, HKDF-SHA256.
- **D04:** File chunking — 1MB chunks, bounded lookahead.
- **D05:** Header serialization — Canonical JSON only.
- **D06:** Inner-wrap bounds — AAD binding across the full document context.
- **D07:** Metadata AEAD — Separate encryption context.
- **D08:** Password rotation — Rotation requires complete re-encryption.
- **D09:** Recovery fallbacks — Retain previous snapshot until atomic rename succeeds.
- **D10:** Vault locking — Cooperative lock files.
- **D11:** KDF parameter upgrades — Silent upgrade upon successful decryption and save.
- **D12:** FIPS compliance mode — Deferred.
- **D13:** Text armour — `BEGIN SSC MESSAGE` block.
- **D14:** CLI routing — Explicit `--with` and auto-detect decrypt.

## 4. Requirement-to-Packet Mapping

| Section | Requirement | Packet | Status |
|---|---|---|---|
| §4 | Sequential PRs | Guide | Consolidated up to P06 |
| §8.1 | Header format | P04 | Unstarted |
| §8.2 | Writer/reader order | P04 | Unstarted |
| §9.1 | File layout | P04 | Unstarted |
| §9.2 | Framing rules | P04 | Unstarted |
| §9.3 | Atomic output | P04 | Partial (atomic_io exists) |
| §9.4 | Metadata AEAD | P04 | Unstarted |
| §9.5 | Text message | P04 | Unstarted |
| §12 | CLI | P07 | Unstarted |
| §13 | CI Matrix | P08 | Unstarted |

## 5. T01-T26 Test Compliance

| ID | Description | Packet | Status |
|---|---|---|---|
| T01 | Legacy preservation | P05 | Assumed |
| T02 | Package/value types | P01 | Partial |
| T03 | Strict header parser | P04 | Unstarted |
| T04 | Rejection before work | P04 | Partial |
| T05 | Derivation vectors | P03 | Not Met |
| T06 | Grant transcripts | P03 | Not Met |
| T07 | Combined secrecy | P03 | Not Met |
| T08 | File boundaries | P04 | Unstarted |
| T09 | Frame adversaries | P04 | Unstarted |
| T10 | Resource limits | P04 | Unstarted |
| T11 | Atomic output | P04 | Partial |
| T12 | Metadata privacy | P04 | Unstarted |
| T13 | Message armour | P04 | Unstarted |
| T14 | Keyfile validation | P02 | Partial |
| T15 | Vault bridge | P05 | Mostly Met |
| T16 | Migration | P06 | Mostly Met |
| T17 | Root persistence | P06 | Partial |
| T18 | Inner record binding | P06 | Partial |
| T19 | Password rotation | P06 | Partial |
| T20 | Concurrency | P05 | Partial (macOS only) |
| T21 | Lifecycle/recovery | P06 | Partial |
| T22 | Multi-resource | P06 | Not Met |
| T23 | CLI routing | P07 | Unstarted |
| T24 | Sensitive output | P07 | Partial |
| T25 | Platform/backend | P08 | Not Met |
| T26 | Packaging/release | P08 | Partial |

## 6. Outer-Vault Document Bridge Design

`passphrase_manager.py` implements a generic translation layer. Legacy flat documents and V2 structured documents are unified in a temporary representation. The storage backend provides atomic backup files (`.bak`) before saving. Rollback restores the `.bak` on failure. Read-after-write authentication guarantees the file on disk matches the serialized snapshot.

## 7. Shared-Lock Design

`vault_lock.py` uses cooperative, platform-specific lock files (`fcntl.flock` on Unix-like, `msvcrt` on Windows) alongside the target file. The timeout semantics allow graceful failure during concurrent writes.

## 8. Proposed Schemas and Binary Constants

- Protocol Prefix: `SSC2` (4 bytes)
- Frame Prefix: `S2FR` + `0x01` (5 bytes)
- Armour Header: `-----BEGIN SSC MESSAGE-----`
- Keyfile Extension: `.ssckey`

## 9. Golden-Fixture Layout

The `tests/fixtures/v2/manifest.json` acts as an immutable baseline containing input-output pairs for HKDF, Argon2, all 3 grant types (password, managed-key, combined), vault inner-wrapping, keyfile format, and schema migration.

## 10. Dependency-Ordered Sequence

Follow the plan in `implementation_plan.md`:
Phase 0 → Git Hygiene
Phase 1 → P00 Reconciliation
Phase 2 → Golden Vectors
Phase 3 → P04 Payload/Metadata
Phase 4 → Independent Reviews
Phase 5 → P07 CLI
Phase 6 → P08 Release Readiness
Phase 7 → Version Bump

## 11. Recovery/Downgrade Procedure

If V2 migration fails, the `passphrase_manager.py` rollback restores the V1 flat file format. The CLI tools provide no automated downgrade from a successful V2 migration to V1, ensuring forwards-only schema progression. External keyfiles can be destroyed with `--confirm` for recovery.

## 12. Validation Commands

```bash
uv sync --extra dev --locked
make ci
uv run --locked pytest tests/ --cov=secure_string_cipher --cov-report=term-missing --cov-fail-under=85 -n 0
```

## 13. Conflicts and Alternatives

None identified at this stage. Spec is unambiguous.
