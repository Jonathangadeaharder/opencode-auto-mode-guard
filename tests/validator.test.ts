import { mkdtemp, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { describe, expect, it, vi } from "vitest"
import { createValidator } from "../.opencode/auto-mode-guard/validator"
import { createMockClient } from "./helpers/mock-client"

describe("validator", () => {
  it("skips checks when project has no tsconfig or biome config", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "amg-validator-"))
    const client = createMockClient()
    const shell = vi.fn()

    const validator = createValidator({
      client,
      $: shell,
      directory: root,
    })

    const result = await validator.runForSession("session-1", {
      sessionID: "session-1",
      reasons: ["edit"],
      files: ["src/a.ts"],
      lastMutationAt: new Date().toISOString(),
    })

    expect(result.ok).toBe(true)
    expect(shell).not.toHaveBeenCalled()
  })

  it("injects repair prompt when typecheck fails", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "amg-validator-fail-"))
    await writeFile(
      path.join(root, "package.json"),
      JSON.stringify({ scripts: { typecheck: "tsc --noEmit" } }),
    )
    await writeFile(path.join(root, "tsconfig.json"), "{}")

    const client = createMockClient()
    const shell = vi.fn(() => ({
      quiet: () => ({
        nothrow: async () => ({
          exitCode: 1,
          stdout: "",
          stderr: "type error TS1234",
        }),
      }),
    }))

    const validator = createValidator({
      client,
      $: shell,
      directory: root,
    })

    const result = await validator.runForSession("session-2", {
      sessionID: "session-2",
      reasons: ["edit"],
      files: ["src/a.ts"],
      lastMutationAt: new Date().toISOString(),
    })

    expect(result.ok).toBe(false)
    expect(client.session.prompt).toHaveBeenCalled()
  })
})
