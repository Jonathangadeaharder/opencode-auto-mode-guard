import type { PolicyVerdict } from "./policy"
import type { SemanticClassifierVerdict } from "./classifier"
import type { AutoModeGuardConfig } from "./config"

export type BlockOutcome = "recover" | "escalate" | "ask"

export interface BlockDecision {
  outcome: BlockOutcome
  message: string
}

interface SessionBlockState {
  consecutive: number
  total: number
}

export function createBlockHandler(config: AutoModeGuardConfig) {
  const bySession = new Map<string, SessionBlockState>()

  return {
    recordAllow(sessionID?: string) {
      if (!sessionID) return
      const state = bySession.get(sessionID)
      if (state) {
        state.consecutive = 0
      }
    },

    decideBlock(
      sessionID: string | undefined,
      source: "policy" | "classifier" | "ask",
      details: {
        policyVerdict?: PolicyVerdict
        classifierVerdict?: SemanticClassifierVerdict
        tool: string
        reason: string
      },
    ): BlockDecision {
      if (source === "ask") {
        return {
          outcome: "ask",
          message: buildAskMessage(details.tool, details.reason, details.policyVerdict, details.classifierVerdict),
        }
      }

      const state = sessionID ? getState(bySession, sessionID) : undefined
      if (state) {
        state.consecutive += 1
        state.total += 1
      }

      const consecutive = state?.consecutive ?? 1
      const total = state?.total ?? 1
      const shouldEscalate =
        consecutive >= config.escalation.consecutiveBlocks || total >= config.escalation.totalBlocks

      if (shouldEscalate) {
        return {
          outcome: "escalate",
          message: buildEscalationMessage(details.tool, details.reason, consecutive, total, details),
        }
      }

      return {
        outcome: "recover",
        message: buildRecoveryMessage(details.tool, details.reason, details),
      }
    },
  }
}

export function buildEscalationPrompt(message: string): string {
  return `${message}

Ask the user explicitly for permission before retrying this class of action.`
}

function getState(map: Map<string, SessionBlockState>, sessionID: string): SessionBlockState {
  const existing = map.get(sessionID)
  if (existing) return existing

  const created = { consecutive: 0, total: 0 }
  map.set(sessionID, created)
  return created
}

function buildRecoveryMessage(
  tool: string,
  reason: string,
  details: {
    policyVerdict?: PolicyVerdict
    classifierVerdict?: SemanticClassifierVerdict
  },
): string {
  const lines = [
    "Auto Mode Guard blocked this tool call.",
    "Do not stop the task. Choose a materially safer approach that stays within the user's explicit request, or ask the user for concrete permission for this exact action.",
    `Tool: ${tool}`,
    `Reason: ${reason}`,
  ]

  appendDetails(lines, details)
  return lines.join("\n")
}

function buildEscalationMessage(
  tool: string,
  reason: string,
  consecutive: number,
  total: number,
  details: {
    policyVerdict?: PolicyVerdict
    classifierVerdict?: SemanticClassifierVerdict
  },
): string {
  const lines = [
    "Auto Mode Guard blocked repeated risky actions and now requires explicit user approval.",
    `Consecutive blocks: ${consecutive}. Total blocks this session: ${total}.`,
    "Stop retrying similar actions until the user explicitly approves them.",
    `Tool: ${tool}`,
    `Reason: ${reason}`,
  ]

  appendDetails(lines, details)
  return lines.join("\n")
}

function buildAskMessage(
  tool: string,
  reason: string,
  policyVerdict?: PolicyVerdict,
  classifierVerdict?: SemanticClassifierVerdict,
): string {
  const lines = [
    "Auto Mode Guard requires explicit user approval before this action can run.",
    "Ask the user to confirm this exact action. Do not proceed until they approve.",
    `Tool: ${tool}`,
    `Reason: ${reason}`,
  ]

  appendDetails(lines, { policyVerdict, classifierVerdict })
  return lines.join("\n")
}

function appendDetails(
  lines: string[],
  details: {
    policyVerdict?: PolicyVerdict
    classifierVerdict?: SemanticClassifierVerdict
  },
) {
  if (details.classifierVerdict?.requiredUserClarification?.trim()) {
    lines.push(`Required clarification: ${details.classifierVerdict.requiredUserClarification.trim()}`)
  }

  if (details.policyVerdict?.normalized) {
    lines.push(`Normalized command: ${details.policyVerdict.normalized}`)
  }

  if (details.policyVerdict?.paths?.length) {
    lines.push(`Paths: ${details.policyVerdict.paths.join(", ")}`)
  }
}
