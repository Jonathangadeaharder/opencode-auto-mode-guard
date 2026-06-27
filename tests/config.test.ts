import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { afterEach, describe, expect, it } from "vitest"
import { loadAutoModeGuardConfig, matchesAnyPattern, matchesPattern } from "../.opencode/auto-mode-guard/config"

describe("config", () => {
  const tempDirs: string[] = []

  afterEach(async () => {
    tempDirs.length = 0
  })

  it("matches glob patterns", () => {
    expect(matchesPattern("git *", "git status")).toBe(true)
    expect(matchesPattern("github.com/org/*", "github.com/org/repo")).toBe(true)
    expect(matchesPattern("git push *", "git status")).toBe(false)
    expect(matchesAnyPattern(["origin", "upstream"], "origin")).toBe(true)
  })

  it("loads defaults when no config files exist", async () => {
    const root = await createTempDir(tempDirs)
    const config = await loadAutoModeGuardConfig(root)

    expect(config.ask.tools).toContain("webfetch")
    expect(config.escalation.consecutiveBlocks).toBe(3)
    expect(config.environment.gitRemotes).toEqual([])
  })

  it("merges auto-mode-guard.json and opencode.json sections", async () => {
    const root = await createTempDir(tempDirs)

    await mkdir(path.join(root, ".opencode"), { recursive: true })
    await writeFile(
      path.join(root, ".opencode/auto-mode-guard.json"),
      JSON.stringify({
        environment: { gitRemotes: ["origin"] },
        escalation: { consecutiveBlocks: 5 },
      }),
    )
    await writeFile(
      path.join(root, "opencode.json"),
      JSON.stringify({
        autoModeGuard: {
          environment: { domains: ["api.example.com"] },
          ask: { bash: ["npm publish *"] },
        },
      }),
    )

    const config = await loadAutoModeGuardConfig(root)

    expect(config.environment.gitRemotes).toContain("origin")
    expect(config.environment.domains).toContain("api.example.com")
    expect(config.ask.bash).toContain("npm publish *")
    expect(config.escalation.consecutiveBlocks).toBe(5)
  })
})

async function createTempDir(registry: string[]) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "auto-mode-guard-"))
  registry.push(dir)
  return dir
}
