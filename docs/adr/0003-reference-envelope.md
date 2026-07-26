# ADR 0003: Implement framing before session establishment

- Status: Accepted
- Date: 2026-07-26

## Context

The cross-platform carrier frame must be stable and testable, while choosing a
production session library requires a separate security and FFI evaluation.
Combining these decisions would encourage an unaudited home-grown ratchet.

## Decision

The first executable slice is a binary envelope and AES-256-GCM reference that
accepts a caller-provided 256-bit content key. It proves:

- canonical framing;
- text-safe carrier encoding;
- strict parsing and size limits;
- authentication of routing metadata;
- negative behavior for corruption and wrong keys.

It does not establish, exchange, rotate, recover, or ratchet content keys.

## Consequences

- The code is useful for interoperability work but not production messaging.
- API names and documentation must say “content key” rather than imply a full
  identity or session protocol.
- A reviewed session engine can later feed content keys into the stable frame.
