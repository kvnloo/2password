# Define versioned broker capabilities

Agents need named, scoped operations without choosing a backing credential on every invocation. Source is fork #1 (`10b4748 a75e50b b5459a8 fb8e036`). Reuse policy ideas from `src/capability.ts` (`normalizeDestination`, `destinationAllowed`, `authorizeLease`, `receiptFor`) and `test/capability.test.ts`. Reference passd's `put_capability` and `_validate_capability_invocation`.

1. Define owner-managed, versioned capability definitions with broker-private 1Password selectors, permitted methods and destination path policy, header policy and an authenticated agent scope/host ceiling.
2. Use the pinned contract's canonicalization and authority identity. Keep reveal outside the RLP capability set.
3. Specify the projection exposed to agents and reviewers, including what changes invalidate an approved definition.

Acceptance: test method, cross-origin, path-boundary and host-ceiling denial, version changes, and secret-free descriptors with a fake capability registry.

Branch `rlp/capability`. Base `integration/rlp`. PR title “Define versioned broker capabilities”.
