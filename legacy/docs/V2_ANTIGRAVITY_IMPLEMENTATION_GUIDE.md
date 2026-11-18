# SSC v2 Antigravity Implementation Guide

**Target:** Secure String Cipher v2.0.0 Managed Keys  
**Purpose:** Antigravity implementation and review operating procedure  
**Canonical architecture:** `docs/V2_MANAGED_KEYS_ARCHITECTURE.md`

> This file governs **how Antigravity should implement and review SSC v2**.
> It does **not** replace or reinterpret the canonical architecture.
> If this guide and `docs/V2_MANAGED_KEYS_ARCHITECTURE.md` ever conflict, the
> architecture document wins.

---

## 1. Primary Principle

SSC v2 is security-sensitive, compatibility-sensitive cryptographic software.

The implementation priority order is:

1. **Security invariants**
2. **Exact specification fidelity**
3. **v1 compatibility**
4. **Correctness**
5. **Tests and verification**
6. **Existing repository conventions**
7. **Minimal change scope**
8. **Elegance**

Do not redesign approved architecture during implementation.

If the specification is ambiguous, **stop and report the ambiguity** rather than
choosing an interpretation.

---

## 2. Model Assignment

### Primary implementer

Use:

**Gemini 3.8 Flash — High reasoning**

when available.

It is the default implementation model for PRs 2–8 because the implementation
requires repeated repository inspection, editing, testing, debugging and
verification across long agentic workflows.

Use **Medium** only for mechanical or low-risk work such as:

- documentation cleanup;
- repetitive tests after semantics are already established;
- formatting;
- clearly behaviour-preserving mechanical changes.

### Architecture and specification reviewer

Use:

**Gemini 3.1 Pro — High reasoning**

for:

- interpreting the canonical architecture before implementation;
- deriving exact implementation contracts;
- identifying constraints and forbidden changes;
- reviewing completed work for specification conformance;
- resolving difficult architecture questions.

Its default role is:

> **Did the implementation follow the approved architecture exactly?**

### Independent adversarial reviewer

Use:

**Claude Thinking**  
Prefer the strongest available Sonnet/Opus Thinking model for security-critical
reviews.

Its default role is:

> **How could this implementation be wrong, unsafe or incomplete even if it appears
> to follow the architecture?**

The reviewing Claude agent should normally remain **read-only** until findings
are accepted.

### `/boost`

Reserve `/boost` for:

- cryptographic composition questions;
- ambiguous or conflicting reviewer conclusions;
- protocol/header authentication problems;
- complex binary framing;
- difficult security bugs;
- PRs 5–7 where deeper multi-agent reasoning is justified.

Do not waste `/boost` on routine implementation.

---

## 3. Do Not Use One Model for the Entire v2 Implementation

Do **not** run one long task such as:

> Read the architecture and implement all of SSC v2.

Each architecture PR is a separate implementation and review boundary.

Use a fresh task/context for each PR after the previous PR has passed its review
and verification gate.

This reduces:

- context drift;
- accidental scope expansion;
- architectural improvisation;
- compounding mistakes;
- hidden coupling between incomplete PRs.

---

## 4. Required PR Sequence

Follow the canonical staged plan.

### PR 2 — v2 module skeleton and dataclasses

Primary:
- Gemini 3.8 Flash High

Review:
- Gemini 3.1 Pro High

Scope:
- `src/secure_string_cipher/v2/`
- dataclasses/types
- canonical JSON helper
- no encryption behaviour change

### PR 3 — `.ssckey` keyfile format

Primary:
- Gemini 3.8 Flash High

Review:
- Gemini 3.1 Pro High

Focus:
- read/write/validation
- fingerprint computation
- format stability
- malformed-input handling
- fixtures/tests

### PR 4 — structured v2 vault schema + `V2VaultService`

Primary:
- Gemini 3.8 Flash High

Review:
- Gemini 3.1 Pro High
- Claude Thinking

Focus:
- migration safety
- idempotence
- backups
- rollback
- preservation of v1 passphrase behaviour
- no silent vault corruption

### PR 5 — HKDF + AEAD DEK wrapping

Primary:
- Gemini 3.8 Flash High

Mandatory review:
- Gemini 3.1 Pro High
- Claude Thinking

Use `/boost` when needed.

This is a **cryptographic composition gate**.

Review explicitly:

- DEK/KEK separation;
- HKDF domain separation;
- HKDF salt handling;
- managed-key derivation;
- password derivation boundaries;
- combined-mode derivation;
- nonce uniqueness;
- AEAD AAD binding;
- key-material lifetime;
- error/oracle behaviour;
- tamper tests.

### PR 6 — v2 envelope + header authentication

Primary:
- Gemini 3.8 Flash High

Mandatory review:
- Gemini 3.1 Pro High
- Claude Thinking

Use `/boost` when needed.

Focus:

- canonical JSON;
- protected/unprotected boundaries;
- canonical digests;
- access grant binding;
- fingerprint binding;
- KDF parameter binding;
- metadata authentication;
- exact wire-format fidelity.

**Do not improve or reinterpret the wire format. Implement the approved format
literally.**

### PR 7 — v2 payload encryption + chunk frames

Primary:
- Gemini 3.8 Flash High

Mandatory review:
- Gemini 3.1 Pro High
- Claude Thinking

Use `/boost` when needed.

This is the highest-risk implementation stage because it combines:

- cryptography;
- binary parsing;
- streaming;
- framing;
- filesystem behaviour;
- chunk ordering;
- authentication;
- truncation detection;
- failure atomicity.

Mandatory negative tests include:

- modified protected header;
- modified wrapped DEK;
- modified key fingerprint;
- modified KDF salt;
- modified metadata ciphertext;
- modified chunk index;
- reordered chunks;
- duplicated chunks;
- missing final chunk;
- trailing bytes after final chunk;
- modified authentication tag.

### PR 8 — CLI integration and v1/v2 auto-detection

Primary:
- Gemini 3.8 Flash High

Review:
- Gemini 3.1 Pro High

Focus:

- exact `--with` mapping;
- safe ambiguity rejection;
- interactive mapping;
- v1/v2 decrypt auto-detection;
- no accidental v1 behaviour change;
- no v2 encryption exposure before prerequisite security components exist.

### PR 9 — documentation and release hardening

Primary:
- Gemini 3.8 Flash Medium or High

Review:
- Gemini 3.1 Pro High

Focus:

- migration guide;
- user docs;
- threat model;
- release checklist;
- final architecture/documentation consistency.

---

## 5. Existing v2 Skeleton Must Be Audited First

Before extending `codex/v2-module-skeleton`, run a **read-only** audit using
Gemini 3.1 Pro High.

Required task:

> Audit the existing `codex/v2-module-skeleton` branch against PR 2 of
> `docs/V2_MANAGED_KEYS_ARCHITECTURE.md`. Do not modify anything. Classify every
> relevant part as compliant, incomplete, over-scoped, inconsistent or ambiguous.
> Compare it with current `main`, existing tests and repository conventions.
> Produce an exact gap analysis before recommending changes.

Only after that audit should Gemini 3.8 Flash High make approved corrections.

Do not blindly build later PRs on top of an unaudited skeleton.

---

## 6. Mandatory Task Header for Every Implementation PR

Every Antigravity implementation task should begin with the following contract:

```text
AUTHORITATIVE SPECIFICATION:
docs/V2_MANAGED_KEYS_ARCHITECTURE.md

TASK:
Implement PR <N> only.

PRIORITY ORDER:
1. Security invariants
2. Specification fidelity
3. v1 compatibility
4. Correctness
5. Tests
6. Existing project conventions
7. Minimal change scope
8. Elegance

RULES:
- Do not redesign the approved architecture.
- Do not implement future PR scope.
- Do not modify v1 cryptographic behaviour unless explicitly required by the
  approved PR.
- Do not weaken existing security properties.
- Inspect existing implementation, tests, security docs and relevant audits
  before editing.
- Preserve persistent-format compatibility unless the canonical v2 format
  explicitly introduces a versioned new format.
- Never invent cryptographic primitives.
- Never expose secrets for debugging.
- If the specification is ambiguous, STOP and report the ambiguity instead of
  choosing an interpretation.
- Add or update targeted tests with implementation.
- Run targeted tests during development.
- Inspect the final git diff before declaring completion.
- Report every architectural assumption made.
- Report changed files, commands run, test results and remaining risks.
```

---

## 7. Pre-Implementation Contract Pass

Before a security-sensitive PR begins, Gemini 3.1 Pro High should perform a
read-only specification pass.

Use:

> Do not implement anything. Derive the exact implementation contract for PR
> `<N>` from `docs/V2_MANAGED_KEYS_ARCHITECTURE.md` and the current repository.
> Identify:
>
> - required behaviour;
> - security invariants;
> - compatibility constraints;
> - forbidden changes;
> - public/persistent format constraints;
> - required tests;
> - relevant existing code;
> - unresolved ambiguity.
>
> Cite concrete repository files/functions. Do not resolve ambiguity by
> assumption.

The resulting contract becomes input to the implementation task.

This step is **mandatory for PRs 4–7**.

---

## 8. Independent Review Procedure

The implementation model must not be the only reviewer of its own work.

After implementation:

### Review A — specification conformance

Gemini 3.1 Pro High:

> Compare the implementation against the canonical architecture and the PR
> implementation contract. Do not propose a different architecture. Identify
> deviations, missing requirements, accidental future scope, compatibility
> regressions and insufficient tests.

### Review B — adversarial security review

Claude Thinking:

> Assume the implementation contains at least one subtle flaw. Attempt to find
> it. Review security boundaries, malformed input, tampering, secret handling,
> authentication coverage, parser behaviour, failure atomicity, compatibility,
> downgrade/confusion paths and test gaps. Do not modify code. Produce findings
> first.

For PRs 5–7, both reviews are mandatory.

If reviewers materially disagree, use `/boost` or request a new independent
analysis before accepting the implementation.

---

## 9. One Writer, Multiple Reviewers

For SSC v2 security-critical code:

> **One writer, multiple independent reviewers.**

Do not allow multiple implementation agents to simultaneously modify overlapping
cryptographic or persistent-format components.

Parallel agents may safely perform:

- read-only security analysis;
- compatibility analysis;
- test-gap analysis;
- documentation review.

They should not concurrently modify the same cryptographic path.

---

## 10. Security Boundaries

Antigravity must preserve the existing v1 security surface.

### Never do incidentally

- change v1 algorithms;
- change Argon2id behaviour;
- change existing AES-GCM semantics;
- alter supported v1 ciphertext parsing;
- alter existing vault semantics;
- change CLI secret-input behaviour;
- weaken size limits;
- weaken path/symlink protections;
- weaken authentication-before-publication;
- weaken atomic replacement;
- leak detailed failure information that creates an oracle.

### Never invent

- custom cryptographic primitives;
- custom MAC constructions;
- undocumented key-combination schemes;
- ad-hoc nonce derivation;
- non-canonical persistent encodings.

Use the architecture's approved constructions.

---

## 11. Secret Handling

Agents must never:

- print passwords;
- print master passwords;
- print raw managed key material;
- print DEKs;
- print KEKs;
- print derived vault keys;
- commit real `.ssckey` secrets;
- use real vault contents in tests;
- use real OS keychain credentials;
- pass secrets through command-line arguments for convenience.

Use synthetic test material and temporary isolated fixtures.

---

## 12. Recommended Antigravity Permissions

Use restrictive project permissions.

### Filesystem

- workspace repository: allowed;
- outside-project filesystem: **deny by default**;
- real `~/.secure-cipher`: **deny**;
- real OS keychain: **deny during normal agent work**.

### Safe automatic commands

Examples:

```text
git status
git diff
git log
git show

make test-quick
make test
make lint
make ci

uv run --locked pytest ...
uv run --locked ruff check ...
uv run --locked ruff format --check ...
uv run --locked mypy ...
```

### Require confirmation or manual control

- dependency additions/removals;
- release/tag creation;
- `git push`;
- publishing to PyPI;
- Docker publishing;
- operations touching real vault/keychain data;
- destructive migrations;
- broad filesystem operations.

### Deny

```text
rm -rf
sudo
git reset --hard
git clean -fd
git push --force
uv publish
twine upload
docker push
```

unless the user explicitly takes manual control outside normal agent execution.

---

## 13. Testing Strategy

Testing is part of implementation, not an end-stage cleanup.

During implementation:

1. run the most targeted relevant tests;
2. add negative/tamper tests;
3. run `make test-quick`;
4. run broader affected suites;
5. run `make ci` before declaring the PR implementation complete.

Before release, GitHub CI remains authoritative for:

- Python version matrix;
- platform-specific behaviour;
- lint/format/type checks;
- security scans;
- coverage threshold;
- Linux/macOS/Windows safety tests.

A model claiming correctness is **not a release gate**.

---

## 14. Required Final Report From Every Implementation Agent

Before declaring a task complete, the implementing agent must report:

### Scope
- PR implemented;
- architecture sections followed;
- explicit statement that future-PR scope was not implemented.

### Files
- every changed file;
- why each file changed.

### Verification
- exact commands run;
- targeted test results;
- `make test-quick` result;
- `make ci` result when applicable;
- anything left for remote/cross-platform CI.

### Security/compatibility
- security invariants considered;
- persistent-format effects;
- v1 compatibility effects;
- any assumption made.

### Risks
- unresolved ambiguity;
- untested platform behaviour;
- deferred hardening;
- reviewer findings not yet closed.

No vague completion statement such as "everything looks good" is sufficient.

---

## 15. Stop Conditions

An Antigravity agent must stop implementation and ask for review when:

- the architecture is internally ambiguous;
- current code conflicts with the architecture;
- the requested PR requires future-PR behaviour;
- a change appears to require modifying v1 crypto;
- a persistent format needs reinterpretation;
- a security reviewer finds a plausible unresolved issue;
- tests expose an architectural contradiction rather than an implementation bug;
- two independent reviewers materially disagree on security semantics.

Do not silently choose the most convenient interpretation.

---

## 16. Definition of Done for Each PR

A PR is implementation-complete only when:

- its canonical architecture scope is implemented;
- no future PR scope has leaked in;
- relevant tests exist;
- negative/tamper cases are covered where applicable;
- targeted tests pass;
- local verification passes;
- specification review passes;
- mandatory adversarial review passes;
- final diff has been inspected;
- assumptions/risks are documented;
- v1 compatibility remains intact.

For PRs 5–7, completion additionally requires independent security review.

---

## 17. Final Operating Model

```text
CANONICAL ARCHITECTURE
        |
        v
Gemini 3.1 Pro High
read-only implementation contract
        |
        v
Gemini 3.8 Flash High
single primary implementer
        |
        v
targeted tests / iteration
        |
        +-------------------+
        |                   |
        v                   v
Gemini 3.1 Pro High     Claude Thinking
spec conformance        adversarial security
        |                   |
        +---------+---------+
                  |
                  v
          /boost if needed
                  |
                  v
              make ci
                  |
                  v
          GitHub CI matrix
                  |
                  v
             human approval
```

---

## 18. Core Rule

The goal is **not** to produce the most clever v2 implementation.

The goal is to produce the **smallest, clearest, testable implementation that
faithfully realises the approved architecture without destabilising SSC v1**.

When correctness and novelty conflict, choose correctness.

When elegance and specification fidelity conflict, choose specification
fidelity.

When an assumption and a question conflict, ask the question.
