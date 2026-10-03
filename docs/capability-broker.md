# Capability broker experiment

Status: downstream experiment. Do not promote as a security guarantee yet.

This explores the smallest stronger boundary behind the upstream discussion in
[kitlangton/2password#1](https://github.com/kitlangton/2password/issues/1).

## Credit and provenance

The starting point is Kit Langton's 2password design: `op://` handles, batched
1Password access, fixed failures around plaintext, read-back verification, and
the "never retry a write" invariant.

The contract below also carries forward prior pass-cli/passd experiments around
zero-authority machine identities and exact HITL leases, plus the Hermes work on
destination-bound credential use and PII egress:

- https://github.com/NousResearch/hermes-agent/issues/107700
- https://github.com/NousResearch/hermes-agent/issues/107698
- https://github.com/NousResearch/hermes-agent/issues/102922

The goal is to reuse those invariants, not import Hermes architecture into this
small CLI.

## Threat model

Assume the coding agent can choose arbitrary commands and arguments and may be
prompt-injected. The model must not receive plaintext merely because it can ask
2password to use a credential.

That means `run` is useful but cannot be the strongest primitive: the selected
child receives plaintext and can print or transmit it.

## Narrow waist

```text
1Password custody
    |
    | op:// handle
    v
2password authority
    |
    | short-lived capability lease
    v
private executor
    |
    | destination-bound use
    v
remote service
    |
    | sanitized typed receipt
    v
agent
```

### Custody is not authority

A 1Password desktop session or service-account token proves that the broker can
reach a vault. It should not mean that every process able to invoke the broker
may reveal every reachable field.

Machine identity starts with zero resource grants.

### `secret.use` is not `secret.reveal`

- `secret.use`: perform one approved operation with a secret without returning
  the value.
- `secret.reveal`: return plaintext to the caller.
- `read` and `env resolve` are reveal/materialization paths.
- arbitrary child-process injection remains a separate, weaker primitive.

Do not make either capability imply the other.

## Lease contract

A lease is bound to:

`principal + resource + capability + destination + resource version + expiry + use budget`

Where:

- `principal` is an opaque caller identity, not a display name.
- `resource` is a digest of the full `op://` field reference so durable logs do
  not copy potentially sensitive vault/item names.
- `destination` is required for `secret.use`.
- `resource version` makes rotation invalidate old authority.
- `use budget` must be decremented atomically by the eventual authority store.

The pure code in `src/capability.ts` validates the contract but intentionally
does **not** pretend to provide atomic lease consumption.

## Destination contract

The first HTTP executor should be deliberately boring:

- HTTPS only.
- no URL userinfo.
- exact origin match.
- path-prefix policy with segment boundaries.
- no redirect following.
- no caller-controlled Host override.
- DNS/global-address checks at the connection boundary, not a preflight-only
  check vulnerable to rebinding.
- bounded request and response bodies.
- inject the secret only after policy succeeds.
- redact exact injected values from any response/error before returning it.

The current experiment implements only the deterministic URL-policy portion.
Network execution stays out until DNS pinning and redirect semantics are tested.

## PII and redaction

PII/secret redaction is an egress guardrail, not the privacy boundary.

The private executor and destination policy must already make the operation safe
if redaction misses something. Redaction exists to catch accidental echoes from
an otherwise authorized destination.

Durable receipts should avoid raw `op://` references, URL queries/fragments,
request bodies, response bodies, and secret values.

## Service-account boundary

A dedicated 1Password automation vault is valuable narrowing. It is still
custody scope, not per-operation authority.

A future resident broker should be the component that exercises unattended
credentials. Simply storing a service-account token in a same-user Keychain item
must not be presented as an OS sandbox against an arbitrary local agent.

## Promotion ladder

1. Land the trust-boundary documentation upstream.
2. Prove the pure capability/destination/receipt contract here.
3. Add a network executor with connection-level DNS pinning, no redirects, exact
   secret echo redaction, and deterministic tests.
4. Add durable policy + atomic lease budget consumption.
5. Add HITL approval UX that can tighten destination, expiry, and uses.
6. Only then consider a resident broker for prompt reduction.

## Acceptance criteria for a first real `secret.use` path

- An agent cannot turn an allowed use into plaintext stdout.
- A subdomain, alternate port, redirect, private/rebound address, or mismatched
  path cannot receive the credential.
- Rotation makes an existing lease stale before the next use.
- An exhausted or expired lease fails closed.
- Denied requests do not resolve/reveal the secret.
- Receipts contain no raw credential, raw `op://` name, URL query/fragment, or
  request/response body.
- If the authorized service echoes the credential, the agent receives
  `[REDACTED]`.
- No write or externally visible action is retried after an ambiguous result.
