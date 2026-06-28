import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, it } from "vitest"
import { loadAutoModeGuardConfig } from "../.opencode/auto-mode-guard/config"
import { evaluateStaticCase } from "./evaluate-static"
import { evaluateSemanticCase } from "./evaluate-semantic"
import { loadEvalCases } from "./load-cases"
import { formatSummary, summarizeEval } from "./score"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const harnessRoot = path.join(repoRoot, "fixtures/harness")

const DATASETS = [
  "eval/cases/regression.jsonl",
  "eval/cases/adversarial-smoke.jsonl",
  "eval/cases/adversarial.jsonl",
  "eval/cases/benign.jsonl",
  "eval/cases/overambitious.jsonl",
  "eval/cases/prompt-injection.jsonl",
  "eval/cases/from-claude-logs.jsonl",
] as const

describe("eval report", () => {
  it("prints static and semantic metrics for all corpora", async () => {
    const runId = new Date().toISOString()
    const lines: string[] = [`# Eval report ${runId}`, ""]

    const config = await loadAutoModeGuardConfig(harnessRoot)

    for (const datasetRel of DATASETS) {
      const datasetPath = path.join(repoRoot, datasetRel)
      let cases
      try {
        cases = await loadEvalCases(datasetPath)
      } catch {
        lines.push(`## ${datasetRel}`, "missing", "")
        continue
      }

      const staticRows = await Promise.all(
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

      const staticSummary = summarizeEval(staticRows, {
        runId,
        dataset: path.basename(datasetPath),
        layer: "static",
      })

      lines.push(`## ${datasetRel}`)
      lines.push(formatSummary(staticSummary))

      const semanticCases = cases.filter((row) => row.semanticExpected)
      if (semanticCases.length > 0) {
        const semanticRows = await Promise.all(
          semanticCases.map((caseRow) =>
            evaluateSemanticCase(caseRow, {
              runId,
              dataset: path.basename(datasetPath),
              directory: harnessRoot,
              worktree: harnessRoot,
              config,
            }),
          ),
        )
        const active = semanticRows.filter((row) => !row.skipped)
        if (active.length > 0) {
          const semanticSummary = summarizeEval(
            active.map((row) => ({
              ...row,
              staticDecision: row.semanticDecision ?? row.staticDecision,
            })),
            { runId, dataset: path.basename(datasetPath), layer: "semantic" },
          )
          lines.push("")
          lines.push(formatSummary(semanticSummary))
        }
      }

      lines.push("")
    }

    console.log(lines.join("\n"))
  })
})
