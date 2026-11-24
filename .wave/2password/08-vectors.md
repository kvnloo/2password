# Run SHA-256-pinned RLP vectors in Bun

Both backends need a common conformance gate. Source is W1's eventual `kvnloo/passd` spec/vectors commit and the seams from `19a041c 9e77325 93243bc b8f9f02`.

1. Vendor the shared `spec/vectors/` fixture bytes with source commit and expected SHA-256 per file. Verify completeness and digest before running any cases. Initial coverage is approval required, budget exhaustion, concurrent one-use, credential change, destination mismatch, expiry, metadata-only change, revoked token and zero default access.
2. Add `test/rlp-vectors.test.ts` under normal Bun discovery. Adapt vectors to capability, approval, atomic claim, version, revoke and request/receipt entry points using integer-second deterministic time, sandboxed state, fake op and fake transport. Project the specified fields and error codes, compare concurrent results as multisets and verify a matching injected POST at the fake sink on success.
3. Assert canonical outcomes, budget, disclosure and relevant side effects. Surface unknown or missing cases as failures. Resolve semantic differences with W1 before the conformance claim.

Acceptance: `bun test` and `bun run check` pass offline with all shared vectors. Changed bytes, unknown cases and missing fixtures fail explicitly. Python and Bun use the same pinned bytes.

Branch `rlp/vectors`. Base `rlp/approval` while open, then `integration/rlp`. PR title “Run SHA-256-pinned RLP vectors in Bun”.
