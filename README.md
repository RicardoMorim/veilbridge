# VeilBridge

VeilBridge is an early-stage, clean-room privacy middleware project. Its goal is
to let people exchange end-to-end encrypted payloads through messaging apps they
already use, without operating another chat service.

The host messenger remains responsible for delivery. VeilBridge owns a private
composer, cryptographic sessions, contact discovery, key verification, and local
decryption. In secure mode, the host messenger should receive only a text-safe
ciphertext envelope.

> [!WARNING]
> This repository is a research prototype. It has not been audited and is not
> suitable for protecting real conversations yet. The first code slice is a
> reference envelope implementation, not a complete secure-messaging protocol.

## Principles

- No new social graph or message-delivery service.
- No mandatory invitation exchange between existing users.
- Cross-platform protocol compatibility from the beginning.
- Established cryptographic protocols and reviewed libraries, never novel
  cryptography.
- Explicit platform limitations instead of misleading security promises.
- Privacy-preserving discovery: never upload raw or plainly hashed address books.
- Public requirements, threat model, protocol vectors, and security decisions.

## Initial scope

The first milestone documents the product and security boundaries and implements
a compact, text-safe encrypted envelope reference:

1. Requirements and acceptance criteria.
2. Regulatory context and platform constraints.
3. Threat model and system architecture.
4. TDD protocol framing and content-key encryption reference.
5. Cross-platform test-vector format.

The content-key reference deliberately does **not** implement contact discovery,
identity authentication, forward secrecy, post-compromise security, groups, or
multi-device state. Those require a reviewed session protocol and are tracked as
later milestones.

## Repository layout

```text
docs/                       Requirements, risks, architecture, and decisions
packages/protocol/          TypeScript protocol reference and tests
test-vectors/               Language-neutral interoperability vectors
.github/workflows/          Continuous integration
```

## Development

Requires Node.js 22 or newer.

```bash
npm install
npm test
npm run typecheck
```

## Clean-room policy

VeilBridge does not copy code from SecureChats Keyboard, KryptEY, Oversec, or
similar projects. Public documentation and observed limitations may inform
requirements. Every dependency must have a compatible license and be recorded.

## License

Mozilla Public License 2.0. See `LICENSE`.
