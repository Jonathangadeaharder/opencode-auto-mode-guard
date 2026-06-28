import { describe, expect, it } from "vitest"
import { evaluateOpenCodePermission } from "../.opencode/auto-mode-guard/permissions"

describe("permissions", () => {
  const rules = {
    bash: {
      "*": "allow",
      "docker compose up *": "ask",
      "rm -rf *": "deny",
    },
    edit: "allow",
    webfetch: "deny",
  }

  it("matches specific bash patterns with last-rule semantics", () => {
    expect(evaluateOpenCodePermission(rules, "bash", { command: "git status" })?.action).toBe("allow")
    expect(evaluateOpenCodePermission(rules, "bash", { command: "docker compose up -d" })?.action).toBe("ask")
    expect(evaluateOpenCodePermission(rules, "bash", { command: "rm -rf /tmp/x" })?.action).toBe("deny")
  })

  it("matches tool-level string rules", () => {
    expect(evaluateOpenCodePermission(rules, "edit", { path: "src/a.ts" })?.action).toBe("allow")
    expect(evaluateOpenCodePermission(rules, "webfetch", { url: "https://example.com" })?.action).toBe("deny")
  })

  it("returns undefined when no rule exists", () => {
    expect(evaluateOpenCodePermission(rules, "task", { subagent_type: "explore" })).toBeUndefined()
    expect(evaluateOpenCodePermission(undefined, "bash", { command: "pwd" })).toBeUndefined()
  })
})
