# VeilBridge carrier envelope v1

Status: Experimental executable specification  
Wire prefix: `vb1.`  
Integer byte order: Network byte order (big-endian)

## 1. Purpose

The carrier envelope lets an existing messenger transport opaque authenticated
bytes. It is deliberately smaller and stricter than a general serialisation
format.

This document specifies only framing and the experimental content-key cipher
suite. It does not specify identity, contact discovery, key agreement, session
ratcheting, recovery, or group membership.

Normative terms such as MUST, MUST NOT, and SHOULD are interpreted as described
by RFC 2119 and RFC 8174.

## 2. Text encoding

The binary frame MUST be encoded as unpadded canonical base64url and prefixed
with the ASCII string `vb1.`.

Decoders MUST reject:

- any other prefix;
- empty payloads;
- base64 padding;
- characters outside the base64url alphabet;
- encodings which do not round-trip to the same canonical base64url string.

## 3. Binary frame

| Offset | Bytes | Field | v1 value or meaning |
| ---: | ---: | --- | --- |
| 0 | 2 | Magic | ASCII `VB` (`56 42`) |
| 2 | 1 | Version | `01` |
| 3 | 1 | Message type | `01` = direct |
| 4 | 2 | Cipher suite | `0001` = experimental AES-256-GCM content key |
| 6 | 1 | Critical flags | `00` |
| 7 | 16 | Conversation ID | Opaque identifier |
| 23 | 16 | Sender device ID | Opaque identifier |
| 39 | 8 | Sequence | Unsigned 64-bit integer |
| 47 | 12 | Nonce | Cipher-suite nonce |
| 59 | 4 | Ciphertext length | Unsigned byte count |
| 63 | Variable | Ciphertext | Cipher-suite output including its tag |

The maximum ciphertext length is 49,152 bytes. A decoder MUST require the total
binary length to equal `63 + ciphertext_length`; trailing bytes are forbidden.

An implementation of this version MUST reject unknown versions, message types,
cipher suites, and non-zero critical flags.

The bytes at offsets 0 through 46 inclusive form the canonical authenticated
header supplied to the cipher suite as associated data.

## 4. Cipher suite 0x0001

Cipher suite `0x0001` exists to make the framing boundary executable while the
production session engine is evaluated.

- Algorithm: AES-256-GCM through the platform Web Cryptography implementation.
- Key: exactly 32 bytes, supplied by the caller.
- Nonce: 12 cryptographically random bytes generated for every seal operation.
- Tag: 16 bytes, appended to the ciphertext by AES-GCM.
- Associated data: frame bytes 0 through 46.
- Maximum plaintext: 49,136 bytes.
- Text: UTF-8 encoded before sealing and decoded strictly only after successful
  authentication.

Every seal operation MUST use a fresh nonce for its content key. Metadata
tampering changes the associated data and MUST cause authentication failure.
Implementations SHOULD expose authentication failure without distinguishing
wrong keys from corrupted ciphertext.

The reference makes best-effort attempts to clear mutable key and plaintext byte
copies. It cannot erase immutable JavaScript strings or guarantee erasure by the
runtime.

## 5. Content-key warning

A static shared key with this cipher suite is **not** a secure messaging
protocol. It does not provide:

- peer authentication;
- initial key agreement;
- forward secrecy;
- post-compromise security;
- replay detection;
- safe multi-device membership;
- group state.

Production session output must come from a separately reviewed asynchronous
session protocol. Until then, this suite is for tests and interoperability
experiments only.

## 6. Parsing order

A decoder should:

1. validate the text prefix and canonical base64url;
2. enforce the minimum fixed-header length;
3. check magic, version, type, suite, and critical flags;
4. read and bound the declared ciphertext length;
5. require the exact total frame length;
6. reconstruct the canonical authenticated header;
7. authenticate and decrypt;
8. apply replay/session checks when a session engine exists;
9. decode or render plaintext.

No unauthenticated display metadata should be trusted.

## 7. Vector

`test-vectors/envelope-v1.json` fixes one framing example. Its ciphertext is an
opaque parser value rather than valid AES-GCM output, so it MUST NOT be passed to
the content-key opener. Cryptographic round trips and corruption behavior are
covered by the executable tests.

## 8. Change policy

Any wire-format change requires:

- a requirements reference;
- an ADR explaining compatibility and security impact;
- a failing test before implementation;
- updated language-neutral vectors;
- cross-implementation verification before mobile release.
