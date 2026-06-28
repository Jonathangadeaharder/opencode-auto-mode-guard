import { describe, expect, it } from "vitest"
import { createBlockHandler, buildEscalationPrompt } from "../.opencode/auto-mode-guard/block-handler"
import { createTestConfig } from "./helpers/config"

describe("block-handler", () => {
  const config = createTestConfig({
    escalation: { consecutiveBlocks: 3, totalBlocks: 5 },
  })
  const handler = createBlockHandler(config)

  it("returns ask outcome without incrementing counters", () => {
    const decision = handler.decideBlock("session-1", "ask", {
      tool: "bash",
      reason: "Configured ask rule",
    })

    expect(decision.outcome).toBe("ask")
    expect(decision.message).toContain("explicit user approval")
  })

  it("recovers until consecutive threshold is reached", () => {
    const sessionID = "recover-session"

    const first = handler.decideBlock(sessionID, "classifier", {
      tool: "bash",
      reason: "blocked once",
    })
    const second = handler.decideBlock(sessionID, "classifier", {
      tool: "bash",
      reason: "blocked twice",
    })

    expect(first.outcome).toBe("recover")
    expect(second.outcome).toBe("recover")
    expect(first.message).toContain("Do not stop the task")
  })

  it("escalates after consecutive blocks", () => {
    const sessionID = "escalate-session"

    handler.decideBlock(sessionID, "classifier", { tool: "bash", reason: "1" })
    handler.decideBlock(sessionID, "classifier", { tool: "bash", reason: "2" })
    const third = handler.decideBlock(sessionID, "classifier", { tool: "bash", reason: "3" })

    expect(third.outcome).toBe("escalate")
    expect(third.message).toContain("Consecutive blocks: 3")
  })

  it("escalates after total blocks even if consecutive resets", () => {
    const sessionID = "total-session"
    const localHandler = createBlockHandler(createTestConfig({ escalation: { consecutiveBlocks: 10, totalBlocks: 2 } }))

    localHandler.decideBlock(sessionID, "classifier", { tool: "bash", reason: "1" })
    localHandler.recordAllow(sessionID)
    const second = localHandler.decideBlock(sessionID, "classifier", { tool: "bash", reason: "2" })

    expect(second.outcome).toBe("escalate")
    expect(second.message).toContain("Total blocks this session: 2")
  })

  it("resets consecutive blocks after allow", () => {
    const sessionID = "reset-session"

    handler.decideBlock(sessionID, "classifier", { tool: "bash", reason: "1" })
    handler.decideBlock(sessionID, "classifier", { tool: "bash", reason: "2" })
    handler.recordAllow(sessionID)
    const afterReset = handler.decideBlock(sessionID, "classifier", { tool: "bash", reason: "3" })

    expect(afterReset.outcome).toBe("recover")
    expect(afterReset.message).not.toContain("Consecutive blocks: 3")
  })

  it("builds escalation prompt text", () => {
    expect(buildEscalationPrompt("blocked too often")).toContain("Ask the user explicitly")
  })
})
