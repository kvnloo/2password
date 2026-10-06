import { BunServices } from "@effect/platform-bun"
import { assert, describe, it } from "@effect/vitest"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { Lease } from "../src/lease.js"
import type { Binding } from "../src/request.js"

const resource = { id: "i".repeat(26), version: 7 }
const binding: Binding = {
  capability: "request",
  method: "GET",
  reference: "op://Personal/Example API Key/credential",
  destination: "https://api.example.com/v1/me",
  destinationFingerprint: "a".repeat(64),
  header: "Authorization",
  prefix: "Bearer ",
}

const fixture = async () => {
  const directory = await mkdtemp(join(tmpdir(), "2password-lease-"))
  return {
    path: join(directory, "leases.sqlite"),
    close: () => rm(directory, { recursive: true, force: true }),
  }
}

const grant = (path: string, uses = 1, expiresIn = "10m") =>
  Lease.grantWith({ ...binding }, { path, uses, expiresIn }, () => Effect.succeed(resource))

const fails = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  effect.pipe(
    Effect.map(() => false),
    Effect.catch(() => Effect.succeed(true)),
  )

describe("leases", () => {
  it.runIf(!process.stdin.isTTY || !process.stderr.isTTY)(
    "refuses normal lease minting from a non-interactive agent process",
    async () => {
      const result = await Effect.runPromise(
        fails(Lease.grant(binding, { uses: 1, expiresIn: "10m" })).pipe(Effect.provide(BunServices.layer)),
      )
      assert.isTrue(result)
    },
  )

  it("binds authority and atomically exhausts a use budget", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path, 2))
      assert.strictEqual(created.usesRemaining, 2)
      assert.strictEqual(created.itemVersion, 7)
      assert.strictEqual(created.destinationFingerprint, binding.destinationFingerprint)
      assert.strictEqual(created.fingerprint, createHash("sha256").update(created.id).digest("hex").slice(0, 12))
      assert.isFalse((await readFile(f.path)).toString("utf8").includes(created.id))

      const authorized = await Effect.runPromise(Lease.authorize(created.id, binding, { path: f.path }))
      assert.strictEqual(authorized.issuer, created.issuer)

      const first = await Effect.runPromise(Lease.claim(created.id, binding, resource, { path: f.path }))
      assert.strictEqual(first.usesRemaining, 1)
      const second = await Effect.runPromise(Lease.claim(created.id, binding, resource, { path: f.path }))
      assert.strictEqual(second.usesRemaining, 0)

      const replay = await Effect.runPromise(fails(Lease.claim(created.id, binding, resource, { path: f.path })))
      assert.isTrue(replay)
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("denies binding and credential-version mismatches without spending a use", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path))
      const wrongBinding = { ...binding, destinationFingerprint: "b".repeat(64) }

      assert.isTrue(await Effect.runPromise(fails(Lease.authorize(created.id, wrongBinding, { path: f.path }))))
      assert.isTrue(
        await Effect.runPromise(
          fails(Lease.claim(created.id, binding, { ...resource, version: 8 }, { path: f.path })),
        ),
      )
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 1)
    } finally {
      await f.close()
    }
  })

  it("allows exactly one concurrent claim for a one-use lease", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path))
      const attempts = await Promise.allSettled([
        Effect.runPromise(Lease.claim(created.id, binding, resource, { path: f.path })),
        Effect.runPromise(Lease.claim(created.id, binding, resource, { path: f.path })),
      ])
      assert.strictEqual(attempts.filter(({ status }) => status === "fulfilled").length, 1)
      assert.strictEqual(attempts.filter(({ status }) => status === "rejected").length, 1)
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("revokes immediately and keeps revocation idempotently closed", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path, 3))
      const revoked = await Effect.runPromise(Lease.revoke(created.id, { path: f.path }))
      assert.isTrue(revoked.revoked)
      assert.isTrue(await Effect.runPromise(fails(Lease.authorize(created.id, binding, { path: f.path }))))
      assert.isTrue(await Effect.runPromise(fails(Lease.revoke(created.id, { path: f.path }))))
    } finally {
      await f.close()
    }
  })

  it("burns the claim and withholds the secret if the credential version changes during use", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path))
      let inspections = 0
      let reads = 0
      const resolve = Lease.resolverWith(created.id, binding, { path: f.path }, {
        inspect: () =>
          Effect.sync(() => {
            inspections += 1
            return inspections === 1 ? resource : { ...resource, version: resource.version + 1 }
          }),
        read: () =>
          Effect.sync(() => {
            reads += 1
            return "fictional-private-value"
          }),
      })

      const failed = await Effect.runPromise(fails(resolve(binding.reference)))
      assert.isTrue(failed)
      assert.strictEqual(reads, 1)
      assert.strictEqual(inspections, 2)
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 0)
    } finally {
      await f.close()
    }
  })

  it("expires without spending or reviving a lease", async () => {
    const f = await fixture()
    try {
      const created = await Effect.runPromise(grant(f.path, 1, "1s"))
      await new Promise((resolve) => setTimeout(resolve, 1100))
      assert.isTrue(await Effect.runPromise(fails(Lease.authorize(created.id, binding, { path: f.path }))))
      assert.isTrue(await Effect.runPromise(fails(Lease.claim(created.id, binding, resource, { path: f.path }))))
      assert.strictEqual((await Effect.runPromise(Lease.status(created.id, { path: f.path }))).usesRemaining, 1)
    } finally {
      await f.close()
    }
  })

  it("rejects overbroad lifetimes and budgets before inspecting 1Password", async () => {
    const f = await fixture()
    try {
      let inspected = false
      const inspect = () => {
        inspected = true
        return Effect.succeed(resource)
      }
      const ttl = await Effect.runPromise(
        fails(Lease.grantWith(binding, { path: f.path, uses: 1, expiresIn: "2h" }, inspect)),
      )
      const uses = await Effect.runPromise(
        fails(Lease.grantWith(binding, { path: f.path, uses: 11, expiresIn: "10m" }, inspect)),
      )
      assert.isTrue(ttl)
      assert.isTrue(uses)
      assert.isFalse(inspected)
    } finally {
      await f.close()
    }
  })
})
