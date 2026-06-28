import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { afterEach, describe, expect, it } from "vitest"
import {
  loadAutoModeGuardConfig,
  loadMergedOpenCodeConfig,
  matchesAnyPattern,
  matchesPattern,
  parseModelRef,
  resolveClassifierModel,
} from "../.opencode/auto-mode-guard/config"
import { createTestConfig } from "./helpers/config"

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

  it("parses provider/model refs", () => {
    expect(parseModelRef("anthropic/claude-haiku-4-5")).toEqual({
      providerID: "anthropic",
      modelID: "claude-haiku-4-5",
    })
    expect(parseModelRef("openrouter/mistralai/mistral-small")).toEqual({
      providerID: "openrouter",
      modelID: "mistralai/mistral-small",
    })
  })

  it("resolves Granite Guardian by default", async () => {
    const root = await createTempDir(tempDirs)

    const resolved = await resolveClassifierModel(root, createTestConfig())
    expect(resolved.source).toBe("granite_guardian_default")
    expect(resolved.providerID).toBe("ollama")
    expect(resolved.modelID).toBe("granite4.1-guardian:8b")
  })

  it("resolves classifier model with env override", async () => {
    const root = await createTempDir(tempDirs)

    const previous = process.env.OPENCODE_AUTO_MODE_CLASSIFIER_MODEL
    process.env.OPENCODE_AUTO_MODE_CLASSIFIER_MODEL = "openai/gpt-4.1-mini"

    try {
      const resolved = await resolveClassifierModel(root, createTestConfig())
      expect(resolved.source).toBe("env")
      expect(resolved.modelID).toBe("gpt-4.1-mini")
    } finally {
      if (previous === undefined) {
        delete process.env.OPENCODE_AUTO_MODE_CLASSIFIER_MODEL
      } else {
        process.env.OPENCODE_AUTO_MODE_CLASSIFIER_MODEL = previous
      }
    }
  })

  it("prefers guard classifierModel over default granite", async () => {
    const root = await createTempDir(tempDirs)

    const resolved = await resolveClassifierModel(root, createTestConfig({ classifierModel: "openai/gpt-4.1-mini" }))
    expect(resolved.source).toBe("guard-config")
    expect(resolved.modelID).toBe("gpt-4.1-mini")
  })

  it("loads merged opencode config with project overrides", async () => {
    const root = await createTempDir(tempDirs)
    await writeFile(path.join(root, "opencode.json"), JSON.stringify({ small_model: "anthropic/claude-haiku-4-5" }))
    await mkdir(path.join(root, ".opencode"), { recursive: true })
    await writeFile(
      path.join(root, ".opencode/opencode.json"),
      JSON.stringify({ model: "anthropic/claude-sonnet-4-5" }),
    )

    const merged = await loadMergedOpenCodeConfig(root)
    expect(merged.small_model).toBe("anthropic/claude-haiku-4-5")
    expect(merged.model).toBe("anthropic/claude-sonnet-4-5")
  })
})

async function createTempDir(registry: string[]) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "auto-mode-guard-"))
  registry.push(dir)
  return dir
}
