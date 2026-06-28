import type { PolicyVerdict } from "../.opencode/auto-mode-guard/policy"
import { requiresFullClassifierReview } from "../.opencode/auto-mode-guard/injection-heuristics"

/** Mock Granite Guardian scores for tests and semantic eval fixtures. */
export function guardianPromptTextsForExpected(
  expected: "allow" | "deny",
  input: {
    policyVerdict: PolicyVerdict
    tool: string
    sanitizedArgs?: unknown
    transcript?: string
  },
): string[] {
  const skipQuick =
    input.policyVerdict.risk === "critical" ||
    input.policyVerdict.risk === "high" ||
    requiresFullClassifierReview({
      policyVerdict: input.policyVerdict,
      tool: input.tool,
      sanitizedArgs: input.sanitizedArgs ?? {},
      transcript: input.transcript ?? "",
    })

  if (expected === "allow") {
    return skipQuick ? ["<score>yes</score>"] : ["<score>no</score>", "<score>yes</score>"]
  }

  return skipQuick ? ["<score>no</score>"] : ["<score>yes</score>", "<score>no</score>"]
}
