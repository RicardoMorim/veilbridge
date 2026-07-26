# Product requirements

Status: Baseline v0.1  
Last reviewed: 2026-07-26

## 1. Product intent

VeilBridge is privacy middleware layered over existing messaging applications.
It is not a messenger, social network, or message relay. It gives two registered
users a secure composer and local decryption path while letting their existing
messenger carry an opaque text envelope.

The product must be understandable by a non-technical user and must not require
people who already have each other in their address books to exchange manual key
invitations.

## 2. Stakeholders

- People sending and receiving private messages.
- Contacts who have not installed VeilBridge.
- Security researchers and independent auditors.
- Mobile operating-system and app-store reviewers.
- Messaging applications used only as delivery transports.
- Operators or federations providing discovery and key-transparency services.
- Open-source maintainers and downstream distributors.

## 3. Goals

| ID | Goal | Success signal |
| --- | --- | --- |
| G-01 | Keep secure-mode plaintext out of the host messenger | Only a VeilBridge envelope is committed to the host input field |
| G-02 | Eliminate manual invitations for registered contacts | A registered contact is discovered without sending them a setup message |
| G-03 | Preserve existing messaging habits | Users continue sending through their chosen messenger |
| G-04 | Be cross-platform | Android and iOS implementations consume the same protocol vectors |
| G-05 | Minimise central knowledge | Discovery cannot read uploaded contact identifiers or message content |
| G-06 | Remain accessible | Core software is free, open source, and usable without a paid subscription |
| G-07 | Make trust visible | Key changes, unsupported states, and platform limitations are surfaced clearly |

## 4. Non-goals

VeilBridge does not:

- replace WhatsApp, Messenger, Signal, SMS, email, or their delivery networks;
- hide sender, recipient, timing, IP address, or message-size metadata from every
  observer;
- protect plaintext from a compromised operating system, malicious keyboard,
  screen capture, accessibility malware, a malicious recipient, or forensic
  access to an unlocked endpoint;
- guarantee protection from scanning performed before VeilBridge receives the
  text or after the recipient decrypts it;
- promise to be “Chat Control proof” or guarantee compliance with future law;
- silently encrypt to an unregistered recipient for whom no trustworthy key
  exists;
- invent a cryptographic algorithm.

## 5. Functional requirements

### Identity and devices

- **FR-001** The client shall generate an independent local device identity.
- **FR-002** Long-term private keys shall be non-exportable where platform
  hardware permits it.
- **FR-003** A user shall be able to link multiple devices without exposing a
  reusable plaintext recovery secret to the service.
- **FR-004** A key change shall be visible and shall require explicit recovery or
  verification when transparency checks fail.

### Invite-free discovery

- **FR-010** The client shall discover existing registered contacts without
  sending an invitation message.
- **FR-011** Address-book identifiers shall be normalised locally.
- **FR-012** Raw identifiers and unsalted identifier hashes shall never be
  uploaded.
- **FR-013** The discovery protocol shall use an RFC 9497 VOPRF-compatible design
  or a separately reviewed equivalent.
- **FR-014** Discovery results shall be bound to signed, expiring device key
  packages.
- **FR-015** Clients shall verify append-only key-transparency evidence before
  trusting a newly discovered or changed identity.
- **FR-016** A missing contact shall produce a clear “not protected” state. The
  product shall not silently fall back to plaintext while presenting a secure
  indicator.

### Sending

- **FR-020** Secure-mode text shall be composed inside a VeilBridge-owned private
  editor, not streamed through the host application's input connection.
- **FR-021** The sender shall see the intended recipient identity and protection
  state before encryption.
- **FR-022** The protocol core shall encrypt locally and return a text-safe,
  versioned envelope.
- **FR-023** Only the resulting envelope shall be inserted into the host
  messenger.
- **FR-024** Plaintext shall not be written to logs, analytics, crash reports, or
  persistent drafts by default.
- **FR-025** If the envelope exceeds the selected carrier's safe limit, the client
  shall refuse or split it using an authenticated fragmentation protocol.

### Receiving

- **FR-030** The client shall recognise supported envelopes without treating
  arbitrary text as encrypted content.
- **FR-031** Authentication shall complete before plaintext is displayed.
- **FR-032** Invalid, truncated, replayed, or unsupported envelopes shall fail
  closed with a non-technical explanation.
- **FR-033** Android may offer opt-in local decryption from notification content,
  subject to notification-access permission.
- **FR-034** iOS shall use only supported extension and explicit user-action
  paths; it shall not claim background interception that iOS does not provide.
- **FR-035** Decrypted notification content shall be hidden on the lock screen by
  default.

### Sessions

- **FR-040** Production one-to-one sessions shall provide forward secrecy and
  post-compromise security through a reviewed protocol implementation.
- **FR-041** Group sessions shall use an established group key agreement such as
  MLS (RFC 9420), after a dedicated interoperability and delivery-ordering study.
- **FR-042** Replay detection state shall be local and bounded.
- **FR-043** The host messenger shall not be the authority for cryptographic
  identity.

### User control

- **FR-050** Users shall be able to disable discovery, notification processing,
  and individual carrier integrations independently.
- **FR-051** Users shall be able to delete local identities and request deletion
  of registered discovery records.
- **FR-052** Permissions shall be requested at the moment a feature needs them,
  with a plain-language explanation.

## 6. Quality requirements

| ID | Requirement |
| --- | --- |
| NFR-001 | No production cryptographic primitive may be implemented directly by project code when a suitable reviewed library exists. |
| NFR-002 | Protocol parsers shall reject unknown critical flags, invalid lengths, non-canonical encodings, and unsupported versions. |
| NFR-003 | Every protocol change shall include negative tests and language-neutral vectors. |
| NFR-004 | Android-to-iOS interoperability shall be a release gate, not a later compatibility promise. |
| NFR-005 | Initial setup for an already-registered contact should take under two minutes after installation and permission decisions. |
| NFR-006 | Secure sending should require at most one additional deliberate action compared with ordinary sending. |
| NFR-007 | Services shall retain the minimum data necessary, publish retention periods, and avoid analytics by default. |
| NFR-008 | A discovery operator shall not be a single invisible source of truth; clients shall verify transparency proofs and support independent witnesses. |
| NFR-009 | Sensitive operations and protocol parsing shall be fuzzed before a beta release. |
| NFR-010 | A reproducible build and software bill of materials shall be available before a stable release. |

## 7. MVP acceptance criteria

The research MVP is accepted when:

1. A secure composer produces a wire string that does not contain plaintext.
2. A second reference client decrypts it using the same content key.
3. Altering protected metadata or ciphertext causes authentication failure.
4. The parser rejects malformed, oversized, unsupported, and truncated input.
5. A language-neutral vector describes the exact envelope bytes.
6. Requirements, threat model, architectural decisions, and test traceability are
   present in the repository.
7. CI runs tests and static type checking.

The MVP is **not** a production release because it does not yet establish or
ratchet content keys.

## 8. Product-release acceptance criteria

A mobile beta additionally requires:

1. Private, invite-free discovery between registered test accounts.
2. Verified key transparency with an independently operated witness.
3. A reviewed session protocol providing forward secrecy and post-compromise
   security.
4. Android and iOS interoperability tests.
5. An external cryptographic design review.
6. Platform-policy review and accurate privacy disclosures.
7. No high-severity unresolved findings from fuzzing and dependency analysis.

## 9. Open decisions

- Which identifier-verification providers can minimise disclosure and abuse?
- Whether the first mobile core should use Rust FFI, native platform libraries,
  or a formally specified independent implementation per platform.
- Whether MLS is practical for all conversations or only groups.
- How to synchronise sessions when the carrier reorders, duplicates, edits, or
  truncates messages.
- How recovery can avoid both permanent loss and operator key escrow.
- Which messaging apps reliably preserve the selected text-safe encoding.
