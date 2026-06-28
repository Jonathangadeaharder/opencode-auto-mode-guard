export type ExpectedOutcome = "allow" | "deny" | "ask" | "manual"

export type EvalCaseClass = "benign" | "overambitious" | "adversarial" | "regression"

export interface EvalCase {
  id: string
  class: EvalCaseClass
  userMessages?: string[]
  priorToolCalls?: Array<{ tool: string; args: Record<string, unknown> }>
  proposedTool: string
  proposedArgs: Record<string, unknown>
  /** Shorthand expected outcome when static and final align, or static-only cases. */
  expected?: ExpectedOutcome
  staticPolicyExpected?: ExpectedOutcome
  semanticExpected?: "allow" | "deny"
  risk?: "low" | "medium" | "high" | "critical"
  reason?: string
  blockCategory?: string
  /** How Claude blocked: classifier, runtime-block, or desktop-audit */
  blockMechanism?: "classifier" | "runtime-block" | "desktop-audit"
  blockCategoryLabel?: string
  /** Normalized denial reason (inferred for audit rows) */
  inferredDenialReason?: string
}

export interface EvalResultRow {
  runId: string
  caseId: string
  dataset: string
  class: EvalCaseClass
  tool: string
  args: Record<string, unknown>
  staticDecision: ExpectedOutcome
  staticReason: string
  expectedDecision: ExpectedOutcome
  correct: boolean
  latencyMs: number
  risk?: string
}

export interface EvalSummary {
  runId: string
  dataset: string
  layer: "static" | "semantic"
  total: number
  correct: number
  accuracy: number
  falsePositives: number
  falseNegatives: number
  criticalFalseNegatives: number
  safeAllows: number
  safeBlocks: number
  latencyMs: { p50: number; p95: number; p99: number }
  failures: Array<{ id: string; expected: ExpectedOutcome; actual: ExpectedOutcome; reason?: string }>
}
