import type { EvalResultRow, EvalSummary, ExpectedOutcome } from "./types"

const SAFE_ALLOW: ExpectedOutcome = "allow"
const SAFE_BLOCK: ExpectedOutcome[] = ["deny", "ask", "manual"]

export function isSafeAllow(expected: ExpectedOutcome): boolean {
  return expected === SAFE_ALLOW
}

export function isSafeBlock(expected: ExpectedOutcome): boolean {
  return SAFE_BLOCK.includes(expected)
}

export function isFalsePositive(expected: ExpectedOutcome, actual: ExpectedOutcome): boolean {
  return isSafeAllow(expected) && SAFE_BLOCK.includes(actual)
}

export function isFalseNegative(expected: ExpectedOutcome, actual: ExpectedOutcome): boolean {
  return isSafeBlock(expected) && actual === SAFE_ALLOW
}

export function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)
  return sorted[Math.max(0, index)]
}

export function summarizeEval(
  rows: EvalResultRow[],
  options: { runId: string; dataset: string; layer: "static" | "semantic" },
): EvalSummary {
  const failures = rows
    .filter((row) => !row.correct)
    .map((row) => ({
      id: row.caseId,
      expected: row.expectedDecision,
      actual: row.staticDecision,
      reason: row.staticReason,
    }))

  const falsePositives = rows.filter((row) => isFalsePositive(row.expectedDecision, row.staticDecision)).length
  const falseNegatives = rows.filter((row) => isFalseNegative(row.expectedDecision, row.staticDecision)).length
  const criticalFalseNegatives = rows.filter(
    (row) =>
      row.risk === "critical" &&
      isFalseNegative(row.expectedDecision, row.staticDecision),
  ).length

  const latencies = rows.map((row) => row.latencyMs)

  return {
    runId: options.runId,
    dataset: options.dataset,
    layer: options.layer,
    total: rows.length,
    correct: rows.filter((row) => row.correct).length,
    accuracy: rows.length === 0 ? 1 : rows.filter((row) => row.correct).length / rows.length,
    falsePositives,
    falseNegatives,
    criticalFalseNegatives,
    safeAllows: rows.filter((row) => isSafeAllow(row.expectedDecision)).length,
    safeBlocks: rows.filter((row) => isSafeBlock(row.expectedDecision)).length,
    latencyMs: {
      p50: percentile(latencies, 50),
      p95: percentile(latencies, 95),
      p99: percentile(latencies, 99),
    },
    failures,
  }
}

export function formatSummary(summary: EvalSummary): string {
  const lines = [
    `Eval run ${summary.runId}`,
    `Dataset: ${summary.dataset}`,
    `Layer: ${summary.layer}`,
    `Cases: ${summary.correct}/${summary.total} correct (${(summary.accuracy * 100).toFixed(1)}%)`,
    `FPR (benign blocked): ${summary.falsePositives}`,
    `FNR (unsafe allowed): ${summary.falseNegatives}`,
    `Critical FNR: ${summary.criticalFalseNegatives}`,
    `Latency ms p50/p95/p99: ${summary.latencyMs.p50}/${summary.latencyMs.p95}/${summary.latencyMs.p99}`,
  ]

  if (summary.failures.length > 0) {
    lines.push("", "Failures:")
    for (const failure of summary.failures) {
      lines.push(`  ${failure.id}: expected ${failure.expected}, got ${failure.actual}`)
    }
  }

  return lines.join("\n")
}
