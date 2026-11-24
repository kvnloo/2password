# Require human approval and audit leased requests

The approval interface must distinguish an authenticated reviewer from an agent running in a terminal. Source is upstream #10 (`b8f9f02 a3411f8 9979520 cc16883 2aab799 92ee1c7`), upstream #9’s desktop gate (`93243bc`), and fork #1 receipt work (`10b4748 a75e50b`). Re-cut `src/request-leased.ts` (`LeasedRequest.request`), `src/cli.ts` request/lease commands, and update `src/lease.ts`, request tests and skill.

1. Authenticate agent and reviewer separately. Persist an immutable pending request with reason and authority digest, then approve or deny against its ID and digest. Enforce the owner's one-approval-per-use posture.
2. Route invocation through the version checker, atomic claim and private executor. Isolate custody, store and reviewer operations from the agent's identity including legacy CLI paths and direct op.
3. Provide authorized status and revocation. Emit durable, encrypted, admin-only audit events for request, approval, denial, claim/invocation and revocation, correlating opaque IDs and suppressing credential material and sensitive request metadata. Cover terminal transport and validation failures after lease selection (GAP-6). Reconcile owner-decision proof and its reviewed digest with W1 (GAP-2).

Acceptance: the fake agent cannot mint leases, gain custody or use the owner's revocation route. Altered authority and replay fail closed. One approved use reaches the destination and request/error/revocation events correlate without exposing plaintext.

Branch `rlp/approval`. Base `rlp/version` while open, then `integration/rlp`. PR title “Require human approval and audit leased requests”.
