# Test strategy

VeilBridge uses test-driven development for protocol behavior and security
boundaries.

## Red-green-refactor rule

For each externally visible protocol behavior:

1. **Red:** add a focused failing test and record the failure.
2. **Green:** implement the smallest behavior that makes it pass.
3. **Refactor:** improve structure without changing behavior.
4. Run the complete unit, negative, interoperability, and type-check suites.

The initial repository preserves separate red and green commits so reviewers can
see that the tests fail for the intended reason before implementation exists.

## Test layers

- **Unit:** framing, validation, encoding, associated-data construction.
- **Negative security tests:** corrupted metadata/tag, wrong key, truncation,
  unsupported versions/flags/types, invalid sizes and Unicode.
- **Interoperability vectors:** language-neutral bytes and expected wire strings.
- **Cross-implementation:** the TypeScript and Java implementations both open
  the published AES-GCM vector; Java also reproduces it with injected test
  randomness.
- **Property tests:** round trips and parser invariants over generated inputs.
- **Fuzzing:** parser and state-machine inputs before beta.
- **Platform isolation tests:** verify the host editor never receives secure-mode
  plaintext.
- **End-to-end:** two devices using a real carrier, including duplication,
  reordering, truncation, and app-specific size limits.

## Initial traceability

| Requirement | Tests |
| --- | --- |
| FR-022, MVP-1, MVP-2 | encrypted round trip and text-safe wire |
| FR-031, MVP-3 | wrong key, metadata tamper, ciphertext tamper |
| FR-030, FR-032, MVP-4 | prefix, version, flags, type, truncation, size validation |
| NFR-002 | strict parser suite |
| NFR-003, MVP-5 | deterministic framing vector |
| G-04, NFR-003 | TypeScript/Java content-key vector and Android unit suite |

Discovery, transparency, session ratcheting, and mobile composer requirements are
not marked complete by the reference-protocol tests.

## Android lab gate

The Android workflow uses JDK 17 and the checked-in Gradle wrapper to run:

```text
:protocol:test :app:lintDebug :app:assembleDebug
```

Manual acceptance uses two API 26+ devices, a harmless unique test sentence, a
matching shared test key, and a text carrier. Success requires exact local
decryption on the second device. A wrong key and a one-character carrier
mutation must both fail with `authentication_failed`.

This gate validates the carrier-envelope experiment only. It does not satisfy
the unimplemented discovery, authenticated-session, or production mobile
requirements.
