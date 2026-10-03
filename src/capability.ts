import { createHash } from "node:crypto"

export type Capability = "secret.use" | "secret.reveal"

export interface CapabilityLease {
  readonly principal: string
  readonly resource: string
  readonly capability: Capability
  readonly destination?: string | undefined
  readonly resourceVersion: string
  readonly expiresAt: number
  readonly useBudget: number
}

export interface CapabilityRequest {
  readonly principal: string
  readonly ref: string
  readonly capability: Capability
  readonly destination?: string | undefined
  readonly resourceVersion: string
}

export type Authorization =
  | { readonly allowed: true; readonly destination?: string | undefined }
  | {
      readonly allowed: false
      readonly reason:
        | "principal_mismatch"
        | "resource_mismatch"
        | "capability_mismatch"
        | "destination_required"
        | "destination_denied"
        | "resource_stale"
        | "lease_expired"
        | "lease_exhausted"
    }

export interface UseReceipt {
  readonly resource: string
  readonly capability: Capability
  readonly destination?: string | undefined
  readonly outcome: "allowed" | "denied"
  readonly reason?: Exclude<Authorization, { readonly allowed: true }>["reason"] | undefined
}

const httpsUrl = (input: string): URL | undefined => {
  try {
    const url = new URL(input)
    if (url.protocol !== "https:" || url.username || url.password) return undefined
    return url
  } catch {
    return undefined
  }
}

const policyPath = (url: URL): string => {
  const path = url.pathname.replace(/\/+$/, "")
  return path === "" ? "/" : path
}

const requestPath = (url: URL): string => url.pathname || "/"

export const normalizeDestination = (input: string): string | undefined => {
  const url = httpsUrl(input)
  if (!url) return undefined
  return `${url.origin}${policyPath(url)}`
}

export const destinationAllowed = (policy: string, requested: string): boolean => {
  const allowed = httpsUrl(policy)
  const target = httpsUrl(requested)
  if (!allowed || !target || allowed.origin !== target.origin) return false

  const base = policyPath(allowed)
  const path = requestPath(target)
  if (base === "/") return true
  return path === base || path.startsWith(`${base}/`)
}

// Raw op:// references can contain human-readable vault/item/field names.
// Receipts and durable policy should carry this opaque fingerprint instead.
export const resourceFingerprint = (ref: string): string =>
  createHash("sha256").update(ref, "utf8").digest("hex")

export const authorizeLease = (
  lease: CapabilityLease,
  request: CapabilityRequest,
  now: number = Date.now(),
): Authorization => {
  if (lease.principal !== request.principal) return { allowed: false, reason: "principal_mismatch" }
  if (lease.resource !== resourceFingerprint(request.ref)) return { allowed: false, reason: "resource_mismatch" }
  if (lease.capability !== request.capability) return { allowed: false, reason: "capability_mismatch" }
  if (lease.resourceVersion !== request.resourceVersion) return { allowed: false, reason: "resource_stale" }
  if (lease.expiresAt <= now) return { allowed: false, reason: "lease_expired" }
  if (lease.useBudget <= 0) return { allowed: false, reason: "lease_exhausted" }

  if (request.capability === "secret.use") {
    if (!lease.destination || !request.destination) return { allowed: false, reason: "destination_required" }
    if (!destinationAllowed(lease.destination, request.destination)) {
      return { allowed: false, reason: "destination_denied" }
    }
    return { allowed: true, destination: normalizeDestination(request.destination) }
  }

  return { allowed: true }
}

export const receiptFor = (lease: CapabilityLease, request: CapabilityRequest, authorization: Authorization): UseReceipt => ({
  resource: lease.resource,
  capability: request.capability,
  ...(request.destination === undefined
    ? {}
    : { destination: normalizeDestination(request.destination) ?? "invalid" }),
  outcome: authorization.allowed ? "allowed" : "denied",
  ...(authorization.allowed ? {} : { reason: authorization.reason }),
})

// Exact-value redaction is an egress guardrail, not the authorization boundary.
// Longest-first avoids leaking a longer secret when one secret is a prefix of another.
export const redactExactSecrets = (text: string, secrets: ReadonlyArray<string>): string =>
  [...new Set(secrets.filter(Boolean))]
    .toSorted((a, b) => b.length - a.length)
    .reduce((redacted, secret) => redacted.split(secret).join("[REDACTED]"), text)
