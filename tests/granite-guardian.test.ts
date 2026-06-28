import { describe, expect, it } from "vitest"
import {
  authorizationScoreToDecision,
  buildGuardianBlock,
  buildGuardianGenerationPrefix,
  extractGuardianReasoning,
  isGraniteGuardianModel,
  parseGuardianScore,
  quickFilterNeedsFullReview,
} from "../.opencode/auto-mode-guard/granite-guardian"

describe("granite guardian helpers", () => {
  it("detects granite guardian model refs", () => {
    expect(isGraniteGuardianModel({ providerID: "ollama", modelID: "granite4.1-guardian:8b" })).toBe(true)
    expect(isGraniteGuardianModel({ providerID: "ollama", modelID: "granite-guardian-4.1:8b-q4_k_m" })).toBe(true)
    expect(isGraniteGuardianModel({ providerID: "anthropic", modelID: "claude-sonnet-4-5" })).toBe(false)
  })

  it("builds guardian blocks with criteria and scoring schema", () => {
    const block = buildGuardianBlock("The response is safe.", false)
    expect(block).toContain("<guardian>")
    expect(block).toContain("### Criteria: The response is safe.")
    expect(block).toContain("return 'yes'")
  })

  it("parses score tags and bare yes/no outputs", () => {
    expect(parseGuardianScore("<score>yes</score>")).toBe("yes")
    expect(parseGuardianScore("reasoning\n<score>no</score>")).toBe("no")
    expect(parseGuardianScore("Yes")).toBe("yes")
    expect(parseGuardianScore("garbled")).toBeUndefined()
  })

  it("extracts reasoning traces", () => {
    const text =
      "<think>\nUser only asked for tests.\n</think>\n<score>no</score>"
    expect(extractGuardianReasoning(text)).toContain("User only asked for tests")
  })

  it("maps scores to review and authorization decisions", () => {
    expect(quickFilterNeedsFullReview("yes")).toBe(true)
    expect(quickFilterNeedsFullReview("no")).toBe(false)
    expect(authorizationScoreToDecision("yes")).toBe("allow")
    expect(authorizationScoreToDecision("no")).toBe("deny")
  })

  it("uses think prefix for think mode and closed tags for no-think", () => {
    expect(buildGuardianGenerationPrefix(true)).toBe("<think>\n")
    expect(buildGuardianGenerationPrefix(false)).toContain("</think>")
  })
})
