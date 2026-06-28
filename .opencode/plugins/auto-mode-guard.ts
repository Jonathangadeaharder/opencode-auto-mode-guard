import type { Plugin } from "@opencode-ai/plugin"
import { buildEscalationPrompt, createBlockHandler } from "../auto-mode-guard/block-handler"
import {
  createSemanticClassifier,
  formatSemanticBlock,
  type SemanticClassifierVerdict,
} from "../auto-mode-guard/classifier"
import { loadAutoModeGuardConfig, resolveClassifierModel } from "../auto-mode-guard/config"
import {
  evaluateOpenCodePermission,
  loadOpenCodePermissionRules,
} from "../auto-mode-guard/permissions"
import {
  evaluateToolCall,
  formatPolicyBlock,
  isMutationTool,
  requiresClassifier,
  type PolicyVerdict,
} from "../auto-mode-guard/policy"
import {
  createValidator,
  type PendingValidationState,
} from "../auto-mode-guard/validator"

const SERVICE = "auto-mode-guard"

export const AutoModeGuard: Plugin = async ({ client, $, directory, worktree }) => {
  const root = worktree ?? directory
  const config = await loadAutoModeGuardConfig(root)
  const classifierModel = await resolveClassifierModel(root, config)
  const openCodePermissionRules = await loadOpenCodePermissionRules(root)
  const pendingBySession = new Map<string, PendingValidationState>()
  const runningValidation = new Set<string>()

  const classifier = createSemanticClassifier({
    client,
    directory,
    worktree,
    model: {
      providerID: classifierModel.providerID,
      modelID: classifierModel.modelID,
    },
    log: (level, message, extra) => log(client, level, message, extra),
  })

  const blockHandler = createBlockHandler(config)

  const validator = createValidator({
    client,
    $,
    directory,
    worktree,
    log: (level, message, extra) => log(client, level, message, extra),
  })

  await log(client, "info", "Auto Mode Guard loaded", {
    directory,
    worktree,
    trustedGitRemotes: config.environment.gitRemotes.length,
    trustedDomains: config.environment.domains.length,
    openCodePermissionRules: Boolean(openCodePermissionRules),
    classifierModel: `${classifierModel.providerID}/${classifierModel.modelID}`,
    classifierModelSource: classifierModel.source,
  })

  return {
    "tool.execute.before": async (input: any, output: any) => {
      const sessionID = getSessionID(input)
      const tool = String(input?.tool ?? "")

      if (classifier.isClassifierSession(sessionID)) {
        if (/structured|output|json/i.test(tool)) {
          await log(client, "debug", "Allowing internal classifier output tool", { sessionID, tool })
          return
        }
        throw new Error("Auto Mode Guard internal classifier sessions are not allowed to execute workspace tools.")
      }

      const args = output?.args ?? {}
      const openCodePermission = evaluateOpenCodePermission(openCodePermissionRules, tool, args)
      const verdict = await evaluateToolCall({
        tool,
        args,
        directory,
        worktree,
        config,
        openCodePermission,
      })

      await logVerdict(client, "debug", "Pre-execution policy verdict", tool, verdict)

      if (verdict.decision === "allow") {
        blockHandler.recordAllow(sessionID)
        return
      }

      if (verdict.decision === "ask") {
        await handleBlock(client, blockHandler, sessionID, "ask", {
          tool,
          reason: verdict.reason,
          policyVerdict: verdict,
        })
        return
      }

      if (verdict.decision === "deny" && verdict.denyTier === "hard") {
        await handleBlock(client, blockHandler, sessionID, "classifier", {
          tool,
          reason: verdict.reason,
          policyVerdict: verdict,
        })
        return
      }

      if (!requiresClassifier(verdict)) {
        await handleBlock(client, blockHandler, sessionID, "classifier", {
          tool,
          reason: verdict.reason,
          policyVerdict: verdict,
        })
        return
      }

      const semanticVerdict = await classifier.classify({
        sessionID,
        tool,
        args,
        policyVerdict: verdict,
      })

      await logSemanticVerdict(client, tool, semanticVerdict, verdict)

      if (semanticVerdict.permissionDecision === "allow") {
        blockHandler.recordAllow(sessionID)
        return
      }

      await handleBlock(client, blockHandler, sessionID, "classifier", {
        tool,
        reason: semanticVerdict.reason,
        policyVerdict: verdict,
        classifierVerdict: semanticVerdict,
      })
    },

    "tool.execute.after": async (input: any, output: any) => {
      const sessionID = getSessionID(input)

      if (!sessionID || classifier.isClassifierSession(sessionID)) {
        return
      }

      const tool = String(input?.tool ?? "")
      const args = output?.args ?? {}

      let verdict: PolicyVerdict | undefined
      try {
        verdict = await evaluateToolCall({
          tool,
          args,
          directory,
          worktree,
          config,
          openCodePermission: evaluateOpenCodePermission(openCodePermissionRules, tool, args),
        })
      } catch (error) {
        await log(client, "warn", "Could not re-evaluate tool after execution", {
          tool,
          error: stringifyError(error),
        })
      }

      const shouldValidate = verdict?.mutates === true || isMutationTool(tool)
      if (!shouldValidate) {
        return
      }

      const previous = pendingBySession.get(sessionID)
      pendingBySession.set(sessionID, {
        sessionID,
        reasons: [
          ...(previous?.reasons ?? []),
          verdict?.reason ?? `Tool '${tool}' changed the workspace`,
        ].slice(-12),
        files: unique([
          ...(previous?.files ?? []),
          ...(verdict?.paths ?? []),
        ]).slice(-50),
        lastMutationAt: new Date().toISOString(),
      })

      await log(client, "debug", "Marked session for validation", {
        sessionID,
        tool,
        paths: verdict?.paths ?? [],
      })
    },

    event: async ({ event }: any) => {
      if (event?.type !== "session.idle") {
        return
      }

      const sessionID = getSessionID(undefined, event)
      if (!sessionID || classifier.isClassifierSession(sessionID)) {
        return
      }

      const pending = pendingBySession.get(sessionID)
      if (!pending || runningValidation.has(sessionID)) {
        return
      }

      runningValidation.add(sessionID)
      pendingBySession.delete(sessionID)

      try {
        await validator.runForSession(sessionID, pending)
      } catch (error) {
        await log(client, "error", "Validation engine failed", {
          sessionID,
          error: stringifyError(error),
        })
      } finally {
        runningValidation.delete(sessionID)
      }
    },
  }
}

export default AutoModeGuard

async function handleBlock(
  client: any,
  blockHandler: ReturnType<typeof createBlockHandler>,
  sessionID: string | undefined,
  source: "ask" | "classifier",
  details: {
    tool: string
    reason: string
    policyVerdict?: PolicyVerdict
    classifierVerdict?: SemanticClassifierVerdict
  },
) {
  const decision = blockHandler.decideBlock(sessionID, source, details)

  if (decision.outcome === "escalate" && sessionID) {
    await injectSessionPrompt(client, sessionID, buildEscalationPrompt(decision.message))
  }

  const prefix =
    source === "ask"
      ? formatPolicyBlock(details.policyVerdict ?? {
          decision: "ask",
          risk: "medium",
          mutates: false,
          reason: details.reason,
        })
      : details.classifierVerdict && details.policyVerdict
        ? formatSemanticBlock(details.classifierVerdict, details.policyVerdict)
        : details.policyVerdict
          ? formatPolicyBlock(details.policyVerdict)
          : details.reason

  throw new Error(`${decision.message}\n\n${prefix}`)
}

async function injectSessionPrompt(client: any, sessionID: string, text: string) {
  try {
    await client.session.prompt({
      path: { id: sessionID },
      body: {
        parts: [{ type: "text", text }],
      },
    })
  } catch (error) {
    await log(client, "warn", "Could not inject escalation prompt", {
      sessionID,
      error: stringifyError(error),
    })
  }
}

function getSessionID(input?: any, event?: any): string | undefined {
  const raw =
    input?.sessionID ??
    input?.sessionId ??
    input?.session?.id ??
    input?.message?.sessionID ??
    input?.message?.sessionId ??
    event?.properties?.sessionID ??
    event?.properties?.sessionId ??
    event?.properties?.session?.id

  return typeof raw === "string" && raw.length > 0 ? raw : undefined
}

async function logVerdict(
  client: any,
  level: "debug" | "info" | "warn" | "error",
  message: string,
  tool: string,
  verdict: PolicyVerdict,
) {
  await log(client, level, message, {
    tool,
    decision: verdict.decision,
    denyTier: verdict.denyTier,
    reviewLayer: verdict.reviewLayer,
    risk: verdict.risk,
    mutates: verdict.mutates,
    reason: verdict.reason,
    normalized: verdict.normalized,
    paths: verdict.paths,
  })
}

async function logSemanticVerdict(
  client: any,
  tool: string,
  verdict: SemanticClassifierVerdict,
  policyVerdict: PolicyVerdict,
) {
  await log(client, verdict.permissionDecision === "allow" ? "info" : "warn", "Semantic classifier decision", {
    tool,
    classifierDecision: verdict.permissionDecision,
    classifierRisk: verdict.riskLevel,
    classifierConfidence: verdict.confidence,
    classifierReason: verdict.reason,
    classifierStage: verdict.stage,
    policyReason: policyVerdict.reason,
    reviewLayer: policyVerdict.reviewLayer,
    normalized: policyVerdict.normalized,
    paths: policyVerdict.paths,
  })
}

async function log(
  client: any,
  level: "debug" | "info" | "warn" | "error",
  message: string,
  extra?: Record<string, unknown>,
) {
  try {
    await client?.app?.log?.({
      body: {
        service: SERVICE,
        level,
        message,
        extra,
      },
    })
  } catch {
    const writer = level === "error" ? console.error : level === "warn" ? console.warn : console.log
    writer(`[${SERVICE}] ${level}: ${message}`, extra ?? {})
  }
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))]
}

function stringifyError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`
  }
  return String(error)
}
