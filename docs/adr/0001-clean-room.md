# ADR 0001: Clean-room implementation

- Status: Accepted
- Date: 2026-07-26

## Context

Existing encrypted keyboards demonstrate useful interaction patterns but rely on
manual invitations, platform-specific protocols, clipboard workflows, or
architectures that intentionally avoid networking. VeilBridge requires private
automatic discovery, cross-platform compatibility, transparency, multi-device
evolution, and a materially different secure-composer boundary.

## Decision

Implement VeilBridge from a new repository without copying source from existing
encrypted keyboard or overlay applications.

Public standards, official platform documentation, published research, and
observable product limitations may inform the design. Dependencies must be
separately evaluated, pinned, attributed, and license-compatible.

## Consequences

- Security provenance and licensing are easier to explain.
- The project cannot rely on inherited UI or keyboard implementation work.
- Compatibility must come from a public specification and vectors.
- Similar behavior may be reproduced, but source-level copying is prohibited
  unless a later ADR explicitly evaluates and approves a dependency.
