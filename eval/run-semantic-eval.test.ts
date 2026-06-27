import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { loadAutoModeGuardConfig } from "../.opencode/auto-mode-guard/config"
import { evaluateSemanticCase } from "./evaluate-semantic"
import { loadEvalCases } from "./load-cases"
import { formatSummary, summarizeEval } from "./score"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const harnessRoot = path.join(repoRoot, "fixtures/harness")

const SEMANTIC_DATASETS = [
  "eval/cases/prompt-injection.jsonl",
  "eval/cases/overambitious.jsonl",
  "eval/cases/regression.jsonl",
] as const

async function runSemanticDataset(datasetRel: string) {
  const datasetPath = path.join(repoRoot, datasetRel)
  const cases = (await loadEvalCases(datasetPath)).filter((row) => row.semanticExpected)
  const runId = new Date().toISOString()
  const config = await loadAutoModeGuardConfig(harnessRoot)

  const rows = await Promise.all(
    cases.map((caseRow) =>
      evaluateSemanticCase(caseRow, {
        runId,
        dataset: path.basename(datasetPath),
        directory: harnessRoot,
        worktree: harnessRoot,
        config,
      }),
    ),
  )

  const active = rows.filter((row) => !row.skipped)
  const summary = summarizeEval(
    active.map((row) => ({
      ...row,
      expectedDecision: row.expectedDecision,
      staticDecision: row.semanticDecision ?? row.staticDecision,
    })),
    {
      runId,
      dataset: path.basename(datasetPath),
      layer: "semantic",
    },
  )

  return { summary, rows, active }
}

describe("semantic eval (mocked classifier)", () => {
  for (const datasetRel of SEMANTIC_DATASETS) {
    it(path.basename(datasetRel), async () => {
      const { summary, active } = await runSemanticDataset(datasetRel)

      if (summary.failures.length > 0) {
        console.log(formatSummary(summary))
      }

      expect(active.length).toBeGreaterThan(0)
      expect(summary.criticalFalseNegatives).toBe(0)
      expect(summary.failures).toEqual([])
    })
  }
})
