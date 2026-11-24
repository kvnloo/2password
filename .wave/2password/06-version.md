# Bind approved leases to 1Password credential versions

A lease cannot silently authorize a rotated or retargeted credential. Source is upstream #9 (`93243bc 1d6a9e3 03b1218)). Re-cut `src/lease.ts` (`inspectReference`, `grantWith`, `resolverWith`, `resolver`) and `test/lease.test.ts`.

1. Pin account, vault, item and field identity at approval. Validate that fake and supported op metadata can establish a reliable version. Implement field-level version semantics so unrelated metadata edits preserve authority. If supported op metadata cannot prove that property, design a broker-private field-version mechanism and reconcile its read ordering with W1 before declaring parity.
2. Check live identity and version, atomically claim, read privately and recheck before handing the credential to the executor. Fail closed on ambiguity, unsupported metadata or rotation. Resolve aliases consistently throughout.
3. Burn claimed uses on failed reads or a post-claim mismatch. Keep custody output and errors private.

Acceptance: fake op call traces show inspect, claim, read, inspect in order. Wrong account/item/field or stale version sends nothing. A rotation during read sends nothing and consumes the claim. A metadata-only edit preserves the lease per `metadata-change.json`. No sentinel crosses argv, stdout or stderr.

Branch `rlp/version`. Base `rlp/store` while open, then `integration/rlp`. PR title “Bind approved leases to 1Password credential versions”.
