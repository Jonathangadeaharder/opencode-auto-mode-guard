import path from "node:path"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { createSemanticClassifier } from "../.opencode/auto-mode-guard/classifier"
import { requiresFullClassifierReview } from "../.opencode/auto-mode-guard/injection-heuristics"
import { loadAutoModeGuardConfig } from "../.opencode/auto-mode-guard/config"
import { evaluateStaticCase } from "./evaluate-static"
import { loadEvalCases } from "./load-cases"
import type { EvalCase } from "./types"
import { createMockClient, userMessage } from "../tests/helpers/mock-client"
import { harnessRoot } from "../tests/helpers/paths"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const injectionPath = path.join(repoRoot, "eval/cases/prompt-injection.jsonl")

function messagesFromCase(caseRow: EvalCase) {
  return (caseRow.userMessages ?? []).map((text) => userMessage(text))
}

describe("prompt injection eval", () => {
  it("semanticExpected deny cases are not silently allowed without full-review triggers", async () => {
    const cases = await loadEvalCases(injectionPath)
    const config = await loadAutoModeGuardConfig(harnessRoot)
    const runId = "prompt-injection-static"

    const rows = await Promise.all(
      cases.map((caseRow) =>
        evaluateStaticCase(caseRow, {
          runId,
          dataset: "prompt-injection.jsonl",
          directory: harnessRoot,
          worktree: harnessRoot,
          config,
        }),
      ),
    )

    const semanticDenials = cases.filter((row) => row.semanticExpected === "deny")

    for (const caseRow of semanticDenials) {
      const result = rows.find((row) => row.caseId === caseRow.id)
      expect(result, caseRow.id).toBeDefined()

      if (result!.staticDecision === "allow") {
        const transcript = (caseRow.userMessages ?? [])
          .map((message) => `USER:\n${message}`)
          .join("\n\n---\n\n")

        expect(
          requiresFullClassifierReview({
            policyVerdict: {
              decision: result!.staticDecision,
              risk: caseRow.risk ?? "medium",
              mutates: caseRow.proposedTool === "bash" || ["edit", "write"].includes(caseRow.proposedTool),
              reason: result!.staticReason,
              reviewLayer: ["read", "grep", "glob", "webfetch"].includes(caseRow.proposedTool)
                ? "read"
                : "action",
            },
            tool: caseRow.proposedTool,
            sanitizedArgs: caseRow.proposedArgs,
            transcript,
          }),
          caseRow.id,
        ).toBe(true)
      } else {
        expect(result!.staticDecision, caseRow.id).not.toBe("allow")
      }
    }
  })

  it("injection cases with semanticExpected deny require full classifier review", async () => {
    const cases = await loadEvalCases(injectionPath)
    const config = await loadAutoModeGuardConfig(harnessRoot)

    const semanticDenials = cases.filter((row) => row.semanticExpected === "deny")

    for (const caseRow of semanticDenials) {
      const staticRow = await evaluateStaticCase(caseRow, {
        runId: "prompt-injection-heuristic",
        dataset: "prompt-injection.jsonl",
        directory: harnessRoot,
        worktree: harnessRoot,
        config,
      })

      const transcript = (caseRow.userMessages ?? [])
        .map((message) => `USER:\n${message}`)
        .join("\n\n---\n\n")

      const needsFullReview =
        staticRow.staticDecision === "deny" ||
        requiresFullClassifierReview({
          policyVerdict: {
            decision: staticRow.staticDecision,
            risk: caseRow.risk ?? "medium",
            mutates: caseRow.proposedTool === "bash" || ["edit", "write"].includes(caseRow.proposedTool),
            reason: staticRow.staticReason,
            reviewLayer: ["read", "grep", "glob", "webfetch"].includes(caseRow.proposedTool)
              ? "read"
              : "action",
          },
          tool: caseRow.proposedTool,
          sanitizedArgs: caseRow.proposedArgs,
          transcript,
        })

      expect(needsFullReview, caseRow.id).toBe(true)
    }
  })

  it("mocked classifier cannot quick-filter allow injection traps", async () => {
    const cases = await loadEvalCases(injectionPath)
    const traps = cases.filter(
      (row) =>
        row.semanticExpected === "deny" &&
        (row.blockCategory === "quick-filter-trap" ||
          row.blockCategory === "classifier-jailbreak" ||
          row.blockCategory === "fake-user-auth"),
    )

    for (const caseRow of traps) {
      const client = createMockClient({
        messages: messagesFromCase(caseRow),
        promptTexts: ["<score>no</score>"],
      })

      const classifier = createSemanticClassifier({
        client,
        directory: harnessRoot,
        worktree: harnessRoot,
      })

      const verdict = await classifier.classify({
        sessionID: `injection-${caseRow.id}`,
        tool: caseRow.proposedTool,
        args: caseRow.proposedArgs,
        policyVerdict: {
          decision: "manual",
          risk: caseRow.risk ?? "high",
          mutates: true,
          reason: "Injection eval fixture",
          reviewLayer: caseRow.proposedTool === "read" ? "read" : "action",
        },
      })

      expect(verdict.stage, caseRow.id).toBe("full-review")
      expect(verdict.permissionDecision, caseRow.id).toBe("deny")
      // High-risk traps skip quick filter; full review uses default model only.
      expect(client.session.prompt).toHaveBeenCalledTimes(1)
    }
  })

  it("benign controls can still clear via quick filter", async () => {
    const cases = await loadEvalCases(injectionPath)
    const benign = cases.filter((row) => row.semanticExpected === "allow")

    for (const caseRow of benign) {
      const client = createMockClient({
        messages: messagesFromCase(caseRow),
        promptTexts: ["<score>no</score>"],
      })

      const classifier = createSemanticClassifier({
        client,
        directory: harnessRoot,
        worktree: harnessRoot,
      })

      const verdict = await classifier.classify({
        sessionID: `benign-${caseRow.id}`,
        tool: caseRow.proposedTool,
        args: caseRow.proposedArgs,
        policyVerdict: {
          decision: caseRow.proposedTool === "read" ? "allow" : "manual",
          risk: "low",
          mutates: caseRow.proposedTool !== "read",
          reason: "Benign control",
          reviewLayer: caseRow.proposedTool === "read" ? "read" : "action",
        },
      })

      if (caseRow.proposedTool === "read") {
        expect(verdict.permissionDecision, caseRow.id).toBe("allow")
        continue
      }

      expect(verdict.stage, caseRow.id).toBe("quick-filter")
      expect(verdict.permissionDecision, caseRow.id).toBe("allow")
      expect(client.session.prompt).toHaveBeenCalledTimes(1)
    }
  })
})
