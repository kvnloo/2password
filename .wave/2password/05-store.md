# Persist and atomically consume bounded leases

A shared use budget must survive concurrent processes and revocation. Source is upstream #8 (`9e77325 a953518`), with fork #4's token-at-rest precedent (`e87edca 299eb91`). Re-cut `src/lease-store.ts` (`grant`, `authorize`, `claim`, `status`, `revoke`) and `test/lease-store.test.ts`.

1. Persist immutable authority and expiry/use bounds using broker-owned SQLite. Scope leases to authenticated agents, request/approval identity, capability version, exact destination, and resource version.
2. Make claim a conditional atomic write that checks scope, active state, expiry, version and remaining budget. Use request ID as lease ID, select by expiry then request ID, use RLP time and bounds (60–86,400 seconds and 1–100 uses), and clamp approval to requested limits. Keep the owner deployment policy at one use until Kevin authorizes a change. Persist revocation and keep status scoped.
3. Apply restrictive store access before use. If bearer handles exist, store digests and keep handles out of audit. Define claimed-use behavior during revocation and downstream failure.

Acceptance: independent processes contest one-use and N-use leases, the exact expiry boundary consumes zero, mismatch consumes zero, and revocation prevents subsequent claims without replenishing budget.

Branch `rlp/store`. Base `rlp/request` while open, then `integration/rlp`. PR title “Persist and atomically consume bounded leases”.
