import type { EvalCase, EvalResultRow, ExpectedOutcome } from "./types"
import { createSemanticClassifier } from "../.opencode/auto-mode-guard/classifier"
import { loadAutoModeGuardConfig } from "../.opencode/auto-mode-guard/config"
import { evaluateToolCall, requiresClassifier, type PolicyVerdict } from "../.opencode/auto-mode-guard/policy"
import { evaluateStaticCase } from "./evaluate-static"
import { createMockClient, userMessage } from "../tests/helpers/mock-client"

export interface SemanticEvalOptions {
  runId: string
  dataset: string
  directory: string
  worktree: string
  config?: Awaited<ReturnType<typeof loadAutoModeGuardConfig>>
  client?: ReturnType<typeof createMockClient>
}

export interface SemanticEvalRow extends EvalResultRow {
  semanticDecision?: "allow" | "deny"
  semanticReason?: string
  semanticStage?: string
  skipped?: boolean
  skipReason?: string
}

function messagesFromCase(caseRow: EvalCase) {
  return (caseRow.userMessages ?? []).map((text) => userMessage(text))
}

function buildMockClient(caseRow: EvalCase) {
  const expected = caseRow.semanticExpected
  if (!expected) {
    return createMockClient({ messages: messagesFromCase(caseRow), promptTexts: ["no"] })
  }

  if (expected === "allow") {
    return createMockClient({
      messages: messagesFromCase(caseRow),
      promptTexts: ["no"],
      structuredOutputs: [
        {
          permissionDecision: "allow",
          riskLevel: "low",
          reason: caseRow.reason ?? "Explicitly authorized by eval mock.",
        },
      ],
    })
  }

  return createMockClient({
    messages: messagesFromCase(caseRow),
    promptTexts: ["yes"],
    structuredOutputs: [
      {
        permissionDecision: "deny",
        riskLevel: caseRow.risk ?? "high",
        reason: caseRow.reason ?? "Denied by semantic eval mock.",
      },
    ],
  })
}

export async function evaluateSemanticCase(
  caseRow: EvalCase,
  options: SemanticEvalOptions,
): Promise<SemanticEvalRow> {
  const config = options.config ?? (await loadAutoModeGuardConfig(options.worktree))
  const staticRow = await evaluateStaticCase(caseRow, { ...options, config })
  const semanticExpected = caseRow.semanticExpected

  if (!semanticExpected) {
    return {
      ...staticRow,
      skipped: true,
      skipReason: "No semanticExpected field",
      correct: staticRow.correct,
    }
  }

  if (staticRow.staticDecision === "deny") {
    return {
      ...staticRow,
      semanticDecision: "deny",
      semanticReason: "Static hard deny",
      correct: semanticExpected === "deny",
      skipped: true,
      skipReason: "Static layer already denied",
    }
  }

  const policyVerdict: PolicyVerdict = await evaluateToolCall({
    tool: caseRow.proposedTool,
    args: caseRow.proposedArgs,
    directory: options.directory,
    worktree: options.worktree,
    config,
  })

  if (!requiresClassifier(policyVerdict) && semanticExpected === "allow" && policyVerdict.decision === "allow") {
    return {
      ...staticRow,
      semanticDecision: "allow",
      semanticReason: "Static allow without classifier",
      correct: true,
    }
  }

  const client = options.client ?? buildMockClient(caseRow)
  const classifier = createSemanticClassifier({
    client,
    directory: options.directory,
    worktree: options.worktree,
  })

  const started = performance.now()
  const verdict = await classifier.classify({
    sessionID: `semantic-eval-${caseRow.id}`,
    tool: caseRow.proposedTool,
    args: caseRow.proposedArgs,
    policyVerdict,
  })
  const latencyMs = performance.now() - started

  const semanticDecision = verdict.permissionDecision
  const correct = semanticDecision === semanticExpected

  return {
    ...staticRow,
    semanticDecision,
    semanticReason: verdict.reason,
    semanticStage: verdict.stage,
    latencyMs: staticRow.latencyMs + latencyMs,
    correct,
    expectedDecision: semanticExpected as ExpectedOutcome,
  }
}
