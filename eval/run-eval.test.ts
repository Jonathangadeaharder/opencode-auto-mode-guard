import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { loadAutoModeGuardConfig } from "../.opencode/auto-mode-guard/config"
import { evaluateStaticCase } from "./evaluate-static"
import { loadEvalCases } from "./load-cases"
import { formatSummary, summarizeEval } from "./score"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const harnessRoot = path.join(repoRoot, "fixtures/harness")

async function runDataset(datasetRel: string) {
  const datasetPath = path.join(repoRoot, datasetRel)
  const cases = await loadEvalCases(datasetPath)
  const config = await loadAutoModeGuardConfig(harnessRoot)
  const runId = new Date().toISOString()

  const rows = await Promise.all(
    cases.map((caseRow) =>
      evaluateStaticCase(caseRow, {
        runId,
        dataset: path.basename(datasetPath),
        directory: harnessRoot,
        worktree: harnessRoot,
        config,
      }),
    ),
  )

  return summarizeEval(rows, {
    runId,
    dataset: path.basename(datasetPath),
    layer: "static",
  })
}

describe("eval policy golden sets", () => {
  it("regression.jsonl", async () => {
    const summary = await runDataset("eval/cases/regression.jsonl")
    if (summary.failures.length > 0) {
      console.log(formatSummary(summary))
    }

    expect(summary.criticalFalseNegatives).toBe(0)
    expect(summary.failures).toEqual([])
    expect(summary.accuracy).toBe(1)
  })

  it("adversarial-smoke.jsonl", async () => {
    const summary = await runDataset("eval/cases/adversarial-smoke.jsonl")
    if (summary.failures.length > 0) {
      console.log(formatSummary(summary))
    }

    expect(summary.criticalFalseNegatives).toBe(0)
    expect(summary.failures).toEqual([])
  })
})
