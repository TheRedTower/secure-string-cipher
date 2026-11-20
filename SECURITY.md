# Security policy

SSC has not had an independent security audit. What it protects, and what
it doesn't, is set out in the [threat model](docs/THREAT_MODEL.md).

## Supported versions

| Version | Security fixes |
| --- | --- |
| 3.0.x | Yes |
| 2.x and older | No |

SSC 3.0 uses a new file format and cannot read files made by 2.x. To move
them to 3.0, decrypt them with 2.x first, then encrypt them with 3.0.

## Reporting a vulnerability

Please report it privately, not in a public issue:

1. **GitHub Security Advisories** (preferred): open
   [a private report](https://github.com/TheRedTower/secure-string-cipher/security/advisories/new).
2. **Email:** security@avondenecloud.uk

Include what is affected, how to reproduce it, and the impact you expect.
Never include real passwords, keys, recovery codes or vault contents: a
made-up example is enough.

## What to expect

SSC is maintained by one person, on a best-effort basis.

- The aim is to acknowledge a complete report within seven days.
- Confirmed issues are fixed privately where practical and disclosed in a
  coordinated way once a fix is released, with credit if you want it.
- No response, fix or disclosure date is guaranteed.

## In scope

- Anything that lets someone without a file's ways in read or undetectably
  change its contents.
- A way to make SSC use a revoked vault entry, or skip a check that the
  specs in [docs/spec](docs/spec) require.
- A secret reaching SSC's output, logs or error messages.
- A crafted file, key file or vault that makes SSC crash, hang or use
  unbounded resources.

## Out of scope

The limits the threat model already states, such as a compromised computer,
copies of a file kept before access was removed, and old data that `ssc
shred` can't reach.
