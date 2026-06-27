import { describe, expect, it } from "vitest"
import { createSemanticClassifier } from "../.opencode/auto-mode-guard/classifier"
import { assistantMessage, createMockClient, userMessage } from "./helpers/mock-client"
import { harnessRoot } from "./helpers/paths"

describe("classifier contract", () => {
  it("clears quick filter with no and skips full structured review", async () => {
    const client = createMockClient({
      messages: [userMessage("Fix src/safe.ts and run tests.")],
      promptTexts: ["no"],
    })

    const classifier = createSemanticClassifier({
      client,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    const verdict = await classifier.classify({
      sessionID: "user-session-1",
      tool: "bash",
      args: { command: "pnpm test" },
      policyVerdict: {
        decision: "manual",
        risk: "medium",
        mutates: true,
        reason: "Not on safe-list",
        reviewLayer: "action",
      },
    })

    expect(verdict.permissionDecision).toBe("allow")
    expect(verdict.stage).toBe("quick-filter")
    expect(client.session.prompt).toHaveBeenCalledTimes(1)
  })

  it("runs full review when quick filter returns yes", async () => {
    const client = createMockClient({
      messages: [userMessage("Refactor auth only.")],
      promptTexts: ["yes"],
      structuredOutputs: [
        {
          permissionDecision: "deny",
          riskLevel: "high",
          reason: "Git push was not explicitly requested.",
        },
      ],
    })

    const classifier = createSemanticClassifier({
      client,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    const verdict = await classifier.classify({
      sessionID: "user-session-2",
      tool: "bash",
      args: { command: "git push upstream feature/test" },
      policyVerdict: {
        decision: "manual",
        risk: "high",
        mutates: true,
        reason: "Untrusted push",
        reviewLayer: "action",
      },
    })

    expect(verdict.permissionDecision).toBe("deny")
    expect(verdict.stage).toBe("full-review")
    expect(client.session.prompt).toHaveBeenCalledTimes(2)
  })

  it("builds transcript from user messages and tool calls only", async () => {
    const client = createMockClient({
      messages: [
        userMessage("Push to origin."),
        assistantMessage("I'll inspect the repo first.", [{ tool: "bash", args: { command: "git status" } }]),
      ],
      promptTexts: ["no"],
    })

    const classifier = createSemanticClassifier({
      client,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    await classifier.classify({
      sessionID: "user-session-3",
      tool: "bash",
      args: { command: "git push origin main" },
      policyVerdict: {
        decision: "manual",
        risk: "high",
        mutates: true,
        reason: "Push review",
        reviewLayer: "action",
      },
    })

    const promptText = JSON.stringify(client.promptBodies[0])
    expect(promptText).toContain("USER:")
    expect(promptText).toContain("Push to origin.")
    expect(promptText).toContain("TOOL_CALL: bash")
    expect(promptText).not.toContain("inspect the repo")
  })

  it("fails closed without a session id", async () => {
    const classifier = createSemanticClassifier({
      client: createMockClient(),
      directory: harnessRoot,
    })

    const verdict = await classifier.classify({
      tool: "bash",
      args: { command: "git push" },
      policyVerdict: {
        decision: "manual",
        risk: "high",
        mutates: true,
        reason: "Push review",
      },
    })

    expect(verdict.permissionDecision).toBe("deny")
    expect(verdict.reason).toContain("No session id")
  })

  it("does not leak classifier session ids after review", async () => {
    const client = createMockClient({
      messages: [userMessage("Run tests.")],
      promptTexts: ["no"],
    })

    const classifier = createSemanticClassifier({
      client,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    await classifier.classify({
      sessionID: "user-session-4",
      tool: "bash",
      args: { command: "pnpm test" },
      policyVerdict: {
        decision: "manual",
        risk: "low",
        mutates: false,
        reason: "Review",
        reviewLayer: "action",
      },
    })

    expect(classifier.isClassifierSession("classifier-session-test")).toBe(false)
  })
})
