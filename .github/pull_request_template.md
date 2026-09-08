# Pull request

## Summary

<!-- State the problem, the outcome, and the user-visible effect. -->

## Scope

<!-- List the files or behaviours intentionally changed and anything deferred. -->

## Security and compatibility

<!--
Describe effects on cryptography, authentication, secrets, file/vault formats,
filesystem publication, dependencies, and released-data compatibility. Write
"No security or compatibility impact" only after checking each boundary.
See the security policy: SECURITY.md
-->

## Validation

<!-- List the exact commands run and their results. Include focused regressions. -->

## Maintainer checklist

- [ ] The change is limited to one coherent purpose.
- [ ] New or changed behaviour has positive, rejection, and failure-path tests.
- [ ] Public documentation and limitations match the implementation.
- [ ] Released-format fixtures remain unchanged, or an explicit migration is documented.
- [ ] No passwords, keys, plaintext, tokens, private paths, or generated artifacts were committed.
- [ ] Ruff, mypy, sensitive-output, secret, dependency, test, and coverage checks pass locally where applicable.
- [ ] I reviewed the final diff and resolved every review thread with code or a technical rationale.
- [ ] The exact final commit passes all required protected checks before merge.

Security vulnerabilities must be reported privately under the
[security policy](SECURITY.md), not described in a public pull request.
