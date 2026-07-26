# Security policy

VeilBridge is currently a research prototype and has not received an independent
security audit. Do not use it to protect sensitive real-world communications.

## Reporting a vulnerability

Until a dedicated private reporting address is configured, open a GitHub
security advisory in the repository rather than a public issue. Include affected
versions, reproduction steps, impact, and any suggested mitigation.

Please do not include real message content, private keys, access tokens, or
personal identifiers in a report.

## Supported versions

No version is production-supported yet. Security behavior may change before the
first audited release.

## Security claims

Only capabilities covered by the threat model and passing tests may be described
as implemented. In particular, the reference envelope does not provide identity
discovery, forward secrecy, post-compromise security, or multi-device recovery.
