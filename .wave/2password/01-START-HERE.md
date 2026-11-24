# Start here: 2password RLP implementation queue

Status is design complete for this wave, implementation pending. The local W1 contract and fixtures were reviewed. The committed fixture revision is pending. Use `kvnloo/2password:integration/rlp` as the integration base once the implementation wave is authorized. Seed it from current `upstream/main` at that time. The mapping used the prefetched baseline `e011177`.

1. [02 Cross-platform wording](02-wording.md) — ready, independent quick win.
2. [03 Capability policy](03-capability.md) — pending contract alignment.
3. [04 Bound requests and private injection](04-request.md) — pending 03.
4. [05 Atomic lease store](05-store.md) — pending 04.
5. [06 Credential-version checks](06-version.md) — pending 05.
6. [07 Approval, execution and audit](07-approval.md) — pending 06 and principal boundary agreement.
7. [08 Shared vectors](08-vectors.md) — fixture pinning can start once W1 ships, full parity needs 07.
8. [09 Fork housekeeping](09-housekeeping.md) — close drafts after replacement sources are retained and linked.
9. [10 Upstream decision](10-upstream.md) — Kevin decision after the passd demo.

Re-cut minimal commits on the current upstream baseline. Open small draft PRs on the fork. Independent work targets `integration/rlp`; dependent PRs may target their immediate predecessor while it is open, then rebase and retarget to `integration/rlp` after it lands. All merges target integration. Keep reviewable commits and pass `bun run check` with fake op. Update the shipped skill for user-facing changes. Land transport plumbing without exposing an unleased request path.

If current upstream has an equivalent change, keep its implementation and carry only the uncovered behavior. If a conflict changes authority, public metadata, or secret egress semantics, document the conflict with a conformance case and resolve it against the pinned contract before merging. Keep other contributors' changes out of the re-cut unless already in its upstream baseline.

Upstream re-proposal only after Kevin OK. Keep correspondence and drafts on the fork.
