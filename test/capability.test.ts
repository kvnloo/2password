import { assert, describe, it } from "@effect/vitest"

import {
  authorizeLease,
  destinationAllowed,
  normalizeDestination,
  receiptFor,
  redactExactSecrets,
  resourceFingerprint,
  type CapabilityLease,
} from "../src/capability"

const ref = "op://Personal/OpenAI API Key/credential"
const now = 1_800_000_000_000

const lease = (overrides: Partial<CapabilityLease> = {}): CapabilityLease => ({
  principal: "agent:local",
  resource: resourceFingerprint(ref),
  capability: "secret.use",
  destination: "https://api.example.com/v1",
  resourceVersion: "7",
  expiresAt: now + 60_000,
  useBudget: 2,
  ...overrides,
})

describe("destinationAllowed", () => {
  it("requires HTTPS and exact origin", () => {
    assert.isTrue(destinationAllowed("https://api.example.com/v1", "https://api.example.com/v1/models"))
    assert.isFalse(destinationAllowed("https://api.example.com/v1", "http://api.example.com/v1/models"))
    assert.isFalse(destinationAllowed("https://api.example.com/v1", "https://evil.api.example.com/v1/models"))
    assert.isFalse(destinationAllowed("https://api.example.com/v1", "https://api.example.com:8443/v1/models"))
    assert.isFalse(destinationAllowed("https://api.example.com/v1", "https://user@api.example.com/v1/models"))
  })

  it("uses a path boundary instead of a string prefix", () => {
    assert.isTrue(destinationAllowed("https://api.example.com/v1", "https://api.example.com/v1"))
    assert.isTrue(destinationAllowed("https://api.example.com/v1/", "https://api.example.com/v1/models"))
    assert.isFalse(destinationAllowed("https://api.example.com/v1", "https://api.example.com/v10"))
  })

  it("keeps queries out of policy/receipt destinations", () => {
    assert.strictEqual(
      normalizeDestination("https://api.example.com/v1/models?token=not-for-a-receipt#fragment"),
      "https://api.example.com/v1/models",
    )
  })
})

describe("authorizeLease", () => {
  it("accepts only the exact principal, resource, capability, version, destination, and live budget", () => {
    assert.deepStrictEqual(
      authorizeLease(
        lease(),
        {
          principal: "agent:local",
          ref,
          capability: "secret.use",
          destination: "https://api.example.com/v1/models?limit=1",
          resourceVersion: "7",
        },
        now,
      ),
      { allowed: true, destination: "https://api.example.com/v1/models" },
    )
  })

  it("fails closed on stale rotation and exhausted leases", () => {
    const request = {
      principal: "agent:local",
      ref,
      capability: "secret.use" as const,
      destination: "https://api.example.com/v1/models",
      resourceVersion: "8",
    }
    assert.deepStrictEqual(authorizeLease(lease(), request, now), { allowed: false, reason: "resource_stale" })
    assert.deepStrictEqual(authorizeLease(lease({ useBudget: 0, resourceVersion: "8" }), request, now), {
      allowed: false,
      reason: "lease_exhausted",
    })
  })

  it("does not let reveal and use imply each other", () => {
    assert.deepStrictEqual(
      authorizeLease(
        lease(),
        {
          principal: "agent:local",
          ref,
          capability: "secret.reveal",
          resourceVersion: "7",
        },
        now,
      ),
      { allowed: false, reason: "capability_mismatch" },
    )
  })
})

describe("receipts", () => {
  it("uses an opaque resource fingerprint and strips destination query/fragment", () => {
    const request = {
      principal: "agent:local",
      ref,
      capability: "secret.use" as const,
      destination: "https://api.example.com/v1/models?account=alice@example.com#private",
      resourceVersion: "7",
    }
    const authorization = authorizeLease(lease(), request, now)
    const receipt = receiptFor(lease(), request, authorization)

    assert.strictEqual(receipt.resource, resourceFingerprint(ref))
    assert.notInclude(JSON.stringify(receipt), "OpenAI API Key")
    assert.notInclude(JSON.stringify(receipt), "alice@example.com")
    assert.strictEqual(receipt.destination, "https://api.example.com/v1/models")
  })
})

describe("redactExactSecrets", () => {
  it("redacts every exact echo without exposing a longer overlapping secret", () => {
    assert.strictEqual(
      redactExactSecrets("short=abc long=abcdef again=abcdef", ["abc", "abcdef"]),
      "short=[REDACTED] long=[REDACTED] again=[REDACTED]",
    )
  })
})
