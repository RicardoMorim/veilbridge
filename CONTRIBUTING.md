# Contributing

Contributions are welcome after the initial repository is published.

## Rules

1. Start with a requirement or issue and include its identifier in the change.
2. Add a failing test before protocol implementation.
3. Do not introduce custom cryptographic primitives.
4. Do not copy code from projects excluded by the clean-room ADR.
5. Record every dependency's purpose, license, and security rationale.
6. Update test vectors for wire-format changes.
7. Treat compatibility and security changes as design-review work, not routine
   refactors.

Run before submitting:

```bash
npm test
npm run typecheck
```
