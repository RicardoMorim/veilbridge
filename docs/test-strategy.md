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

Discovery, transparency, session ratcheting, and mobile composer requirements are
not marked complete by the reference-protocol tests.
