# Threat model

Status: Initial design model; requires independent review  
Method: Assets, trust boundaries, adversaries, abuse cases, mitigations

## 1. Assets

- Message plaintext and attachments.
- Long-term identity keys and device credentials.
- Session secrets, epochs, and replay state.
- Address-book membership and identifier-to-key relationships.
- Conversation membership and social-graph information.
- Decrypted notification content.
- User intent: which contact and carrier the user meant to use.

## 2. Trust boundaries

1. **VeilBridge private composer** — temporarily handles plaintext.
2. **Protocol core** — handles plaintext, keys, authenticated metadata, and
   ciphertext.
3. **Platform key store** — protects long-term local secrets.
4. **Host messenger** — receives ciphertext and delivery metadata; it is not
   trusted with plaintext or cryptographic identity.
5. **Discovery and transparency services** — untrusted for confidentiality and
   required to provide verifiable evidence for correctness.
6. **Recipient endpoint** — trusted by the sender only to the extent that the
   recipient is trusted.
7. **Operating system and device firmware** — necessarily trusted for endpoint
   security; outside the cryptographic boundary.

## 3. Adversaries considered

| Adversary | Capability | Expected protection |
| --- | --- | --- |
| Host messenger or its server | Read, store, classify, duplicate, reorder, truncate, or drop transported text | Cannot read authenticated message plaintext produced before insertion |
| Network observer | Observe VeilBridge service and messenger traffic | Cannot read message plaintext or raw discovery identifiers; may learn metadata |
| Malicious discovery operator | Enumerate users, equivocate about keys, omit records | VOPRF limits identifier exposure; transparency proofs/witnesses expose equivocation |
| Malicious or compromised messenger client | Inspect its own input and notification content | Sees only envelopes if secure composer isolation succeeds |
| Device thief | Access a locked device and backups | Hardware-backed keys and encrypted local state limit access |
| Malicious peer | Send malformed, huge, replayed, or forged envelopes | Strict parsing, authentication-before-display, replay window, size limits |
| Supply-chain attacker | Compromise a dependency or build | Pinning, review, SBOM, reproducible builds, signing |

## 4. Explicitly out of scope

VeilBridge cannot reliably protect against:

- an operating system, firmware, root-level implant, or malicious accessibility
  service that captures text before encryption;
- screenshots, shoulder surfing, camera capture, or clipboard managers after
  decryption;
- a recipient who deliberately republishes plaintext;
- coercion or compelled endpoint access;
- traffic analysis based on sender, recipient, time, size, and frequency;
- a host application that blocks, rate-limits, or corrupts VeilBridge envelopes;
- future legal mandates requiring VeilBridge itself or the operating system to
  scan plaintext at an endpoint.

No documentation or UI may describe the system as universally “unreadable” or
“surveillance proof.”

## 5. Critical composer rule

A conventional keyboard normally commits text to the host application's editor
as the user types. That would expose plaintext before encryption and defeat the
product's main purpose.

Secure mode must therefore:

1. keep keystrokes in a VeilBridge-owned editor;
2. avoid host suggestions, learning, clipboard, and draft persistence;
3. show a distinct secure-mode state and intended identity;
4. encrypt on an explicit send/commit action;
5. insert only the final envelope into the host editor;
6. clear best-effort mutable plaintext buffers immediately afterward.

Immutable platform strings and compromised runtimes prevent a guarantee of
perfect memory erasure. Documentation must state this.

## 6. Principal threats and controls

### T-01 Plaintext reaches the carrier

- **Cause:** ordinary input-connection commits, previews, logs, autofill,
  spell-check, accessibility, or crash collection.
- **Controls:** isolated composer; disable learning and suggestions in secure
  mode; no plaintext telemetry; fail closed; instrumented platform tests.
- **Residual risk:** the OS and accessibility services can still observe UI and
  process memory.

### T-02 Contact enumeration

- **Cause:** uploading raw numbers/emails or stable unsalted hashes.
- **Controls:** local canonicalisation, rate-limited VOPRF discovery, abuse
  controls that do not create a global identifier oracle, short-lived results.
- **Residual risk:** a malicious operator can analyse timing and query volume;
  attackers with many verified identifiers may still enumerate them.

### T-03 Directory key substitution

- **Cause:** a directory returns an attacker-controlled public key.
- **Controls:** signed key packages, append-only transparency log, consistency
  proofs, independent witnesses, user-visible key-change recovery.
- **Residual risk:** first contact depends on the chosen authentication and
  transparency model.

### T-04 Replay and reordering

- **Cause:** the carrier duplicates or reorders envelopes.
- **Controls:** authenticated conversation/device identifiers, monotonically
  tracked message generation/sequence, bounded replay state, session protocol
  designed for asynchronous delivery.
- **Residual risk:** denial of service and message suppression remain possible.

### T-05 Parser exploitation

- **Cause:** attacker-controlled text is parsed before authentication.
- **Controls:** small canonical framing, fixed limits, reject unknown critical
  fields, fuzzing, memory-safe shared core, authenticate before UTF-8 decoding.

### T-06 Metadata tampering

- **Cause:** carrier changes conversation, sender-device, version, or sequence.
- **Controls:** canonical header supplied as AEAD associated data.

### T-07 Notification leakage

- **Cause:** plaintext shown on the lock screen or retained in notification
  history.
- **Controls:** ciphertext-only carrier notifications; private local notification
  by default; no plaintext on lock screen; user-controlled previews.

### T-08 Malicious update

- **Cause:** compromised release account or update channel.
- **Controls:** protected branches, mandatory review, signed releases,
  reproducible builds, multiple maintainers, transparent release provenance.

## 7. Security-release gates

No production-security claim is permitted until:

- the session protocol and discovery design receive independent expert review;
- platform tests demonstrate that secure-mode plaintext is not committed to the
  host before encryption;
- all supported implementations pass the same test vectors;
- parser fuzzing and dependency scanning are continuous;
- key-change, replay, recovery, and multi-device behavior are specified;
- a responsible disclosure channel and patch policy are operational.
