# V2 Post-Implementation Hardening Review

**Status:** Complete for this pass. Re-run against a fresh baseline before
citing it as still current — see the "How to keep this current" note at
the end.

## Baseline

| | |
| --- | --- |
| Commit reviewed | `9e57355` (`main`, package release `v2.0.0`) |
| Branch | `main` |
| Python | 3.14.7 (CI matrix: 3.12, 3.13, 3.14) |
| Key dependency versions | `cryptography==50.0.1`, `argon2-cffi==25.1.0`, `pynacl==1.6.2`, `pyperclip==1.11.0`, `wcwidth==0.8.3` |
| Total tests (baseline, before this review's changes) | 1626 passing |
| Total tests (after this review's changes) | 1584 (the ~42-test difference is entirely the dead-function test removal in PR #83, not a coverage loss) |
| CI state | `quality`, `test` (×3 Python versions), `platform-safety` (×3 OS × 3 Python) all green on every PR referenced below |

This review was prompted by a post-v2 hardening handoff document supplied
directly to the reviewing session (not itself checked into this
repository). Per that document's own instruction (Part XIV), nothing in it
was accepted at face value: every finding below was independently verified
against the current repository state before being acted on or dismissed.

## Finding matrix

Status values follow the handoff's own vocabulary
(`CONFIRMED` / `PARTIALLY CONFIRMED` / `NO LONGER APPLIES` / `DISAGREE`).

| ID | Finding | Status | Evidence | Action |
| --- | --- | --- | --- | --- |
| F1 | No custom cryptographic primitives | NO LONGER APPLIES | Only `cryptography`/`argon2-cffi`/`pynacl` used throughout `v2/` | None needed |
| F2 | No DEK caching | NO LONGER APPLIES | No cache of any kind found in `v2/*.py` | None needed |
| F3 | Header needs explicit size/resource limits | NO LONGER APPLIES | `header_parser.py`: 65,536-byte header cap, duplicate-JSON-key rejection, canonical-JSON re-encoding check, unexpected-key rejection at every level | None needed |
| F4 | KDF parameters need minimum/maximum bounds | NO LONGER APPLIES, exceeded | Argon2id parameters are pinned to **exact** required values (`memory_kib==65536`, `time_cost==3`, `parallelism==4`, `version==19`), stricter than a min/max range | None needed |
| F5 | Algorithm allowlists | NO LONGER APPLIES | Every `alg` field is checked against one literal string; no dynamic dispatch exists anywhere in the parser | None needed |
| F6 | Frame parser needs hostile-input limits | NO LONGER APPLIES | `payload.py::FrameReader`: sequential-index enforcement (rejects reorder/repeat/gap), `max_frames` bound, cumulative-plaintext cap, unsupported-flag rejection, exact non-final frame length, trailing-bytes-after-FINAL rejection | None needed |
| F7 | Need fuzz/property/adversarial tests | NO LONGER APPLIES | `tests/fuzz/test_fuzz_encryption.py`, `test_fuzz_payload.py`, `test_fuzz_inputs.py`; `tests/unit/test_v2_properties.py`, `test_v2_inner_record_adversary.py` all exist and pass | None needed |
| F8 | Need golden/invalid vectors | NO LONGER APPLIES | Header, keyfile, migration, and container golden vectors exist, sha256-pinned, decrypt-verified, and tamper-tested (closed in the prior engagement, before this review) | None needed |
| F9 | Threat model should state an honest trusted-boundary | PARTIALLY CONFIRMED, already mostly true | `THREAT_MODEL.md` already states what SSC does/doesn't protect against; §5.3 already discloses the DEK's immutable-copy puncture precisely | None needed |
| F10 | `security.py` has functions with no real call sites (assurance smell) | CONFIRMED | 8 functions (`validate_filename_safety`, `validate_safe_path`, `detect_symlink`, `validate_output_path`, `check_elevated_privileges`, `check_sensitive_directory`, `validate_execution_context`, `create_secure_temp_file`) had no caller reachable from any production entry point in `src/` — `validate_output_path` calls `detect_symlink`/`validate_safe_path`, and `validate_execution_context` calls `check_elevated_privileges`/`check_sensitive_directory`, but nothing outside that 8-function cluster ever called into it. The path/symlink subset was also fully superseded by independent real implementations in `core.py` and `v2/output.py` | **Fixed**: PR #83 |
| F11 | Docker base image not digest-pinned; builder deps unpinned; healthcheck meaningless | CONFIRMED | `Dockerfile` used a mutable `python:3.14-alpine` tag; `pip install build cryptography wcwidth pyperclip` had no version pins; `HEALTHCHECK` ran `python -c "import sys; sys.exit(0)"`, which always passes | **Fixed**: PR #84 |
| F12 | CI missing `actionlint`/`dependency-review-action` | CONFIRMED | Zero matches in `.github/workflows/*.yml` before this review | **Fixed**: PR #84 |
| F13 | Fallback memory wipe does unnecessary multi-pass random overwrite | CONFIRMED | `_fallback_wipe` did 3 random passes + zero-fill; RAM has no magnetic-remanence concern for the random passes to address, and CPython has no dead-store-elimination optimizer for them to defeat | **Fixed**: PR #85 |
| F14 | PyNaCl private-FFI reliance undocumented as a risk | CONFIRMED | `secure_memory.py` imports `nacl._sodium.ffi`/`lib`, PyNaCl's private cffi module, with no inline note on the risk | **Fixed** (documented, not removed): PR #85 |
| F15 | No secret-lifetime inventory | CONFIRMED | No such document existed | **Fixed**: PR #86 (`docs/V2_SECRET_LIFETIME_INVENTORY.md`) — headline finding: the vault master password gets zero `SecureString` treatment anywhere in `passphrase_manager.py`/`v2/vault_service.py`, unlike v1's `core.py` |
| F16 | `SecureString.string`/`SecureBytes.data` are punctured by immediate re-conversion to immutable types | CONFIRMED, not fixed here | `v2/encrypt.py`'s `bytes(val.data)`, `v2/decrypt.py`'s `dek = bytes(secure_dek.data)`; every consumer (`derive_payload_key`, `FrameWriter`/`FrameReader`) requires plain `bytes` | **Documented, deliberately not fixed** — see F15's inventory doc and "Deferred" below |
| F17 | No language-independent SSC2 specification / conformance suite | CONFIRMED | `SSC_V2_REFINED_IMPLEMENTATION_SPEC.md` existed but is a Python-implementation-guide-flavored decision record, not a standalone protocol spec; no conformance tooling existed | **Partially fixed**: PR #87 adds the standalone spec (`docs/SSC2_PROTOCOL_SPECIFICATION.md`); a conformance suite/independent decoder is **not** built — see "Deferred" below |
| F18 | Repository governance/release pipeline maturity | PARTIALLY CONFIRMED | `release.yml` already hard-fails on tag/commit/version mismatches; `ci.yml`'s `quality` job already runs `pip-audit` and `detect-secrets` on every PR — but see F12 | F12's fixes close the concrete gaps found |
| F19 | Native/Rust `ssc-core` boundary, opaque secret providers (`SecretHandle`), process isolation | Out of scope by explicit instruction | These are all Part VIII–X of the handoff, and the user explicitly scoped this review to "only v2 is properly implemented" — no v3/native-boundary code | **DEFER**, and correctly so — see Part XV of the handoff itself: "do not mix v3 implementation into v2 hardening" |
| F20 | v3 policy model, threshold recovery, hardware-backed identities, etc. | Out of scope by explicit instruction | v3 design-only per the handoff's own Phase D; no v3 code exists or was added | **DEFER** — design-only work, not started in this review |

## PRs produced by this review

| PR | Title | Closes |
| --- | --- | --- |
| [#83](https://github.com/TheRedTower/secure-string-cipher/pull/83) | Remove 8 unused security-policy helper functions | F10 |
| [#84](https://github.com/TheRedTower/secure-string-cipher/pull/84) | Pin Docker base image digest, lock builder deps, add actionlint + dependency-review | F11, F12 |
| [#85](https://github.com/TheRedTower/secure-string-cipher/pull/85) | Simplify fallback memory wipe, document PyNaCl private-FFI risk | F13, F14 |
| [#86](https://github.com/TheRedTower/secure-string-cipher/pull/86) | Add v2/vault secret lifetime inventory | F15, F16 (documented) |
| [#87](https://github.com/TheRedTower/secure-string-cipher/pull/87) | Extract standalone, language-independent SSC2 protocol spec | F17 (partial) |

Each PR has one coherent purpose, per the handoff's "no bundled mega-PRs"
rule (Part XIV §31, Part XV §33). None of them touch v3.

## What this review deliberately did not do

Consistent with Part XV of the handoff ("Prohibited shortcuts") and the
user's explicit instruction that only v2 gets real implementation changes
in this pass:

- **Did not retrofit `SecureString` through the vault's call graph** (F16).
  The master password is a plain `str` argument on dozens of methods across
  `passphrase_manager.py` and `v2/vault_service.py`. Fixing this properly
  is a real, separately-scoped refactor with its own regression risk —
  documented as the top follow-up candidate in
  `V2_SECRET_LIFETIME_INVENTORY.md`, not attempted here.
- **Did not build a conformance suite or an independent second decoder**
  (F17). The new protocol spec makes that possible in principle, but
  actually writing a second implementation (even a minimal test harness in
  another language) is a substantial standalone project, not a hardening
  PR.
- **Did not touch anything native/Rust, provider/`SecretHandle`, or
  process-isolation related** (F19). No evidence in this codebase suggests
  Python is currently the limiting factor for any of v2's actual
  operations — introducing that machinery without evidence would be
  exactly the "rewrite for language prestige" the handoff itself warns
  against (Part I §1, item 9; Part XV).
- **Did not start any v3 design or implementation work** (F20). Out of
  scope for a v2 hardening pass by both the handoff's own phase gating and
  the user's explicit instruction this session.
- **Did not touch `ssc start`'s lack of v2 support.** Unrelated to
  hardening findings; still tracked in `ROADMAP.md`/the prior review's
  backlog as a larger, separately-scoped feature-parity item.

## How to keep this current

This document is a snapshot as of commit `9e57355` plus the five PRs
above. Before relying on it:

1. Confirm the PRs above actually merged (`git log --oneline main | grep
   -E '#8[3-7]'`) — this document was written while they were still open.
2. Re-run the verification steps that produced each `CONFIRMED` finding
   (they're one-line greps in most cases — see each PR's description) to
   confirm nothing regressed.
3. Treat `V2_SECRET_LIFETIME_INVENTORY.md` and
   `SSC2_PROTOCOL_SPECIFICATION.md` as living documents, not one-time
   artifacts — re-verify their claims against the code before trusting
   them in a future review, the same way this review re-verified the
   original handoff instead of copying it forward.
