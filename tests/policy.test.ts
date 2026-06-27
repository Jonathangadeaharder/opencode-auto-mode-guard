import path from "node:path"
import { describe, expect, it } from "vitest"
import {
  evaluateToolCall,
  normalizeCommand,
  requiresClassifier,
} from "../.opencode/auto-mode-guard/policy"
import { evaluateOpenCodePermission, loadOpenCodePermissionRules } from "../.opencode/auto-mode-guard/permissions"
import { createTestConfig } from "./helpers/config"
import { harnessRoot } from "./helpers/paths"

describe("policy", () => {
  const config = createTestConfig({
    environment: {
      gitRemotes: ["origin", "github.com/test-org/*"],
      domains: ["api.trusted.example.com"],
    },
    ask: {
      bash: ["docker compose up *"],
      tools: ["webfetch"],
    },
  })

  it("normalizes obfuscated shell commands", () => {
    expect(normalizeCommand("git$IFSstatus")).toBe("git status")
  })

  it("allows safe in-workspace edits", async () => {
    const verdict = await evaluateToolCall({
      tool: "edit",
      args: { filePath: "src/safe.ts" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("allow")
    expect(verdict.reviewLayer).toBe("action")
  })

  it("routes sensitive file mutations to semantic review", async () => {
    const verdict = await evaluateToolCall({
      tool: "edit",
      args: { filePath: ".github/workflows/ci.yml" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("manual")
    expect(verdict.risk).toBe("high")
    expect(requiresClassifier(verdict)).toBe(true)
  })

  it("hard-denies secret reads and writes", async () => {
    const envPath = path.join(".env")

    const readVerdict = await evaluateToolCall({
      tool: "read",
      args: { filePath: envPath },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })
    const writeVerdict = await evaluateToolCall({
      tool: "write",
      args: { filePath: envPath },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(readVerdict.decision).toBe("deny")
    expect(readVerdict.denyTier).toBe("hard")
    expect(readVerdict.reviewLayer).toBe("read")
    expect(writeVerdict.decision).toBe("deny")
    expect(writeVerdict.denyTier).toBe("hard")
  })

  it("hard-denies destructive bash", async () => {
    const verdict = await evaluateToolCall({
      tool: "bash",
      args: { command: "sudo rm -rf /" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("deny")
    expect(verdict.denyTier).toBe("hard")
  })

  it("allows trusted git push remotes", async () => {
    const verdict = await evaluateToolCall({
      tool: "bash",
      args: { command: "git push origin feature/test" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("allow")
  })

  it("requires semantic review for untrusted git push", async () => {
    const verdict = await evaluateToolCall({
      tool: "bash",
      args: { command: "git push upstream feature/test" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("manual")
    expect(requiresClassifier(verdict)).toBe(true)
  })

  it("allows safe bash commands", async () => {
    const verdict = await evaluateToolCall({
      tool: "bash",
      args: { command: "git status --short" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("allow")
  })

  it("marks configured bash patterns as ask", async () => {
    const verdict = await evaluateToolCall({
      tool: "bash",
      args: { command: "docker compose up -d" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("ask")
  })

  it("routes untrusted webfetch through read-layer review", async () => {
    const webConfig = createTestConfig({
      environment: config.environment,
      ask: { bash: [], tools: [] },
    })

    const verdict = await evaluateToolCall({
      tool: "webfetch",
      args: { url: "https://unknown.example.com/docs" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config: webConfig,
    })

    expect(verdict.decision).toBe("manual")
    expect(verdict.reviewLayer).toBe("read")
  })

  it("allows trusted webfetch domains", async () => {
    const webConfig = createTestConfig({
      environment: config.environment,
      ask: { bash: [], tools: [] },
    })

    const verdict = await evaluateToolCall({
      tool: "webfetch",
      args: { url: "https://api.trusted.example.com/health" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config: webConfig,
    })

    expect(verdict.decision).toBe("allow")
    expect(verdict.reviewLayer).toBe("read")
  })

  it("honors opencode permission allow and deny before static policy", async () => {
    const allowed = await evaluateToolCall({
      tool: "bash",
      args: { command: "git push upstream feature/test" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
      openCodePermission: { action: "allow", reason: "OpenCode allow rule" },
    })
    const denied = await evaluateToolCall({
      tool: "bash",
      args: { command: "git status" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
      openCodePermission: { action: "deny", reason: "OpenCode deny rule" },
    })

    expect(allowed.decision).toBe("allow")
    expect(denied.decision).toBe("deny")
    expect(denied.denyTier).toBe("hard")
  })

  it("routes unknown tools to semantic review", async () => {
    const verdict = await evaluateToolCall({
      tool: "custom_mcp_tool",
      args: { action: "deploy" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("manual")
    expect(verdict.reviewLayer).toBe("action")
  })

  it("hard-denies workspace escape attempts", async () => {
    const verdict = await evaluateToolCall({
      tool: "read",
      args: { filePath: "/etc/passwd" },
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
    })

    expect(verdict.decision).toBe("manual")
    expect(verdict.reviewLayer).toBe("read")
  })
})

describe("harness fixture permissions", () => {
  it("loads opencode.json permission rules from the fixture repo", async () => {
    const rules = await loadOpenCodePermissionRules(harnessRoot)
    expect(rules).toBeDefined()

    const verdict = evaluateOpenCodePermission(rules, "bash", { command: "docker compose up -d" })
    expect(verdict?.action).toBe("ask")
  })
})
