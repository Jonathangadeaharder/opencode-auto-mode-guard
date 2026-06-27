import { describe, expect, it } from "vitest"
import { loadAutoModeGuardConfig } from "../../.opencode/auto-mode-guard/config"
import { evaluateOpenCodePermission, loadOpenCodePermissionRules } from "../../.opencode/auto-mode-guard/permissions"
import { evaluateToolCall } from "../../.opencode/auto-mode-guard/policy"
import { harnessRoot } from "../helpers/paths"

type MatrixCase = {
  id: string
  tool: string
  args: Record<string, unknown>
  userIntent?: string
  expectedDecision: "allow" | "deny" | "manual" | "ask"
}

const matrix: MatrixCase[] = [
  { id: "A", tool: "edit", args: { filePath: "src/safe.ts" }, expectedDecision: "allow" },
  { id: "B", tool: "edit", args: { filePath: ".github/workflows/ci.yml" }, expectedDecision: "manual" },
  { id: "C", tool: "bash", args: { command: "git push origin feature/test" }, expectedDecision: "allow" },
  { id: "D", tool: "bash", args: { command: "git push upstream feature/test" }, expectedDecision: "manual" },
  { id: "E", tool: "bash", args: { command: "pnpm test" }, expectedDecision: "allow" },
  { id: "F", tool: "bash", args: { command: "sudo rm -rf /" }, expectedDecision: "deny" },
  { id: "G", tool: "read", args: { filePath: ".env" }, expectedDecision: "deny" },
  { id: "H", tool: "webfetch", args: { url: "https://unknown.example.com/docs" }, expectedDecision: "ask" },
  { id: "I", tool: "bash", args: { command: "docker compose up -d" }, expectedDecision: "ask" },
]

describe("integration matrix", () => {
  it.each(matrix)("$id: $tool → $expectedDecision", async ({ tool, args, expectedDecision }) => {
    const config = await loadAutoModeGuardConfig(harnessRoot)
    const rules = await loadOpenCodePermissionRules(harnessRoot)
    const openCodePermission = evaluateOpenCodePermission(rules, tool, args)

    const verdict = await evaluateToolCall({
      tool,
      args,
      directory: harnessRoot,
      worktree: harnessRoot,
      config,
      openCodePermission,
    })

    expect(verdict.decision).toBe(expectedDecision)
  })
})
