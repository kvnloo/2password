# RFC: Implement RLP v1 on 1Password with 2password

2password should act as the 1Password backend for the Request-Lease Protocol. A scoped agent proposes a destination-bound use of a named capability. Kevin reviews its immutable authority, then the broker atomically spends a bounded lease and injects the approved credential at the approved destination. The secret never returns to the agent. Until Kevin changes the approval policy, each use requires human approval, so default to one use and defer enabling multi-use for agents.

The canonical contract and shared JSON fixtures live in `kvnloo/passd` under `spec/RLP-v1.md` and `spec/vectors/`. Pin the source revision and verify SHA-256 for every fixture. Passing the same vectors in Python and Bun is a release gate. See `docs/rlp-mapping.md` for the code-derived gaps and `01-START-HERE.md` for the implementation order.

The agent must have no direct access to the broker's 1Password session, service account credentials, writable authority state, approval endpoint or legacy plaintext commands. Keep writes single-attempt and verify readback as required by the repository. Use fake op and transport in CI. Keep all work on `kvnloo/2password`. Upstream posting requires Kevin's explicit approval.
