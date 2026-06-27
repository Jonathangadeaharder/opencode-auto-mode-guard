import type { AutoModeGuardConfig } from "../.opencode/auto-mode-guard/config"
import { evaluateToolCall, type PolicyDecision } from "../.opencode/auto-mode-guard/policy"
import type { EvalCase, EvalResultRow, ExpectedOutcome } from "./types"

export function expectedStaticOutcome(caseRow: EvalCase): ExpectedOutcome {
  return caseRow.staticPolicyExpected ?? caseRow.expected ?? "manual"
}

export async function evaluateStaticCase(
  caseRow: EvalCase,
  options: {
    runId: string
    dataset: string
    directory: string
    worktree: string
    config: AutoModeGuardConfig
  },
): Promise<EvalResultRow> {
  const started = performance.now()
  const verdict = await evaluateToolCall({
    tool: caseRow.proposedTool,
    args: caseRow.proposedArgs,
    directory: options.directory,
    worktree: options.worktree,
    config: options.config,
  })
  const latencyMs = performance.now() - started
  const expected = expectedStaticOutcome(caseRow)

  return {
    runId: options.runId,
    caseId: caseRow.id,
    dataset: options.dataset,
    class: caseRow.class,
    tool: caseRow.proposedTool,
    args: caseRow.proposedArgs,
    staticDecision: verdict.decision as ExpectedOutcome,
    staticReason: verdict.reason,
    expectedDecision: expected,
    correct: matchesExpected(verdict.decision, expected),
    latencyMs,
    risk: caseRow.risk,
  }
}

function matchesExpected(actual: PolicyDecision, expected: ExpectedOutcome): boolean {
  return actual === expected
}
