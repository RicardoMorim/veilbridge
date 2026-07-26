# ADR 0002: Do not operate a message-delivery service

- Status: Accepted
- Date: 2026-07-26

## Context

The product is intended to preserve existing messaging habits. Operating a
parallel message service would create another account system, social graph,
availability dependency, abuse surface, and data-retention obligation.

## Decision

Existing messaging applications carry VeilBridge ciphertext envelopes. Project
services are limited to identity verification, privacy-preserving discovery,
public key packages, and key transparency.

## Consequences

- VeilBridge cannot guarantee delivery, ordering, deletion, or availability.
- Session protocols must tolerate asynchronous, duplicated, reordered, and
  occasionally corrupted carrier messages.
- Carrier metadata remains visible to the carrier.
- An optional future delivery service requires a new ADR and threat-model review.
