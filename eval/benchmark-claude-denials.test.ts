import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { loadAutoModeGuardConfig } from "../.opencode/auto-mode-guard/config"
import { evaluateStaticCase } from "./evaluate-static"
import { loadEvalCases } from "./load-cases"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const harnessRoot = path.join(repoRoot, "fixtures/harness")

/**
 * Reports how our static policy routes Claude-denied cases.
 * Semantic denials expect staticPolicyExpected=manual (classifier path).
 * Runtime sleep blocks are policy-orthogonal — Claude blocks polling style.
 */
describe("claude log denial benchmark (static routing)", () => {
  it("from-claude-logs.jsonl denials route to manual or deny", async () => {
    const cases = await loadEvalCases(path.join(repoRoot, "eval/cases/from-claude-logs.jsonl"))
    const denials = cases.filter((row) => row.expected === "deny")
    const config = await loadAutoModeGuardConfig(harnessRoot)
    const runId = "claude-denial-benchmark"

    const rows = await Promise.all(
      denials.map((caseRow) =>
        evaluateStaticCase(caseRow, {
          runId,
          dataset: "from-claude-logs",
          directory: harnessRoot,
          worktree: harnessRoot,
          config,
        }),
      ),
    )

    const byDecision = rows.reduce<Record<string, number>>((acc, row) => {
      acc[row.staticDecision] = (acc[row.staticDecision] ?? 0) + 1
      return acc
    }, {})

    const semanticDenials = denials.filter((row) => row.semanticExpected === "deny")
    const staticAllowsOnSemanticDenials = rows.filter(
      (row, index) =>
        denials[index]?.semanticExpected === "deny" && row.staticDecision === "allow",
    )

    const categoryCounts = denials.reduce<Record<string, number>>((acc, row) => {
      const key = row.blockCategory ?? "unknown"
      acc[key] = (acc[key] ?? 0) + 1
      return acc
    }, {})

    console.log("Claude denial static routing:", byDecision)
    console.log("Denial categories:", categoryCounts)
    if (staticAllowsOnSemanticDenials.length > 0) {
      console.log(
        "Static ALLOW on semantic denials (classifier must catch):",
        staticAllowsOnSemanticDenials.map((r) => ({
          id: r.caseId,
          tool: r.tool,
          category: denials.find((d) => d.id === r.caseId)?.blockCategory,
        })),
      )
    }

    // Every semantic denial should at least reach manual/ask/deny — never bare allow
    for (const row of rows) {
      const caseRow = denials.find((d) => d.id === row.caseId)
      if (caseRow?.semanticExpected === "deny") {
        expect(row.staticDecision).not.toBe("allow")
      }
    }

    expect(semanticDenials.length).toBeGreaterThan(0)
    expect(denials.length).toBeGreaterThan(30)
  })
})
