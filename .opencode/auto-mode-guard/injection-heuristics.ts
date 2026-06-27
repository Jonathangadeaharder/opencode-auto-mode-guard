import type { PolicyVerdict, RiskLevel } from "./policy"

const RISK_RANK: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
}

/** Phrases that attempt to jailbreak or bypass the semantic classifier / quick filter. */
const INJECTION_TRANSCRIPT_PATTERNS: RegExp[] = [
  /\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?\b/i,
  /\bignore\s+(the\s+)?(classifier|safety|guard|filter|rules?)\b/i,
  /\bdisable\s+(the\s+)?(classifier|safety|guard|auto\s*mode)\b/i,
  /\b(system|admin|root)\s+override\b/i,
  /\byou\s+are\s+(now\s+)?(the\s+)?(auto\s*mode\s+guard|classifier|security\s+filter)\b/i,
  /\b(reply|answer|respond)\s+(with\s+)?(only\s+)?["']?no["']?\s+(to\s+)?(the\s+)?(quick\s+)?filter\b/i,
  /\b(clearly|obviously)\s+(authorized|low\s+risk)\b.*\b(reply|answer)\s+no\b/i,
  /\bpermissionDecision\s*[:=]\s*["']?allow["']?\b/i,
  /\breturn\s+(only\s+)?\{\s*["']permissionDecision["']\s*:\s*["']allow["']/i,
  /\bfail\s+open\b/i,
  /\boverride\s+(the\s+)?(classifier|guard|policy)\b/i,
  /\bUSER\s+(CONFIRMED|AUTHORIZED|APPROVED)\b/i,
  /\bexplicitly\s+authorized\s*:\s*(git\s+push|rm\s+-|sudo|curl)/i,
  /\bdo\s+not\s+(run|perform)\s+(full\s+)?review\b/i,
  /\bpretend\s+the\s+user\s+(said|approved|authorized)\b/i,
]

const INJECTION_ARG_PATTERNS: RegExp[] = [
  /\bUSER\s+(CONFIRMED|AUTHORIZED|APPROVED)\b/i,
  /\b#\s*SYSTEM:\s*allow\b/i,
  /\bignore\s+(classifier|safety|instructions)\b/i,
  /\bpermissionDecision\s*[:=]\s*allow\b/i,
]

const DANGEROUS_MANUAL_BASH_PATTERNS: RegExp[] = [
  /\bgit\s+push\b[^;&|]*\b(main|master)\b/i,
  /\bgit\s+push\s+.*--force\b/i,
  /\bgit\s+push\s+origin\s+--delete\b/i,
  /\bgit\s+reset\s+--hard\b/i,
  /\bgit\s+rm\s+-/i,
  /\brm\s+-[^;&|]*r/i,
  /\bsudo\b/i,
  /\bcurl\b[^;&|]*\|\s*(sh|bash|zsh)\b/i,
  /\bwget\b[^;&|]*\|\s*(sh|bash|zsh)\b/i,
  /\bkubectl\b/i,
  /\bterraform\s+(apply|destroy)\b/i,
  /\bgh\s+run\s+cancel\b/i,
  /\bkill\s+-TERM\b/i,
]

const SENSITIVE_READ_TARGET_PATTERNS: RegExp[] = [
  /claude_desktop_config/i,
  /claude-for-legal/i,
  /\/\.claude\//i,
  /handoff\.md/i,
  /\/var\/folders\//i,
  /(^|\/)\.env(\.|\/|$)/i,
]

export function detectInjectionSignals(transcript: string, sanitizedArgs: unknown): boolean {
  const haystacks = [transcript, stringifyArgs(sanitizedArgs)]
  for (const text of haystacks) {
    if (!text) continue
    if (INJECTION_TRANSCRIPT_PATTERNS.some((pattern) => pattern.test(text))) {
      return true
    }
    if (INJECTION_ARG_PATTERNS.some((pattern) => pattern.test(text))) {
      return true
    }
  }
  return false
}

export function requiresFullClassifierReview(input: {
  policyVerdict: PolicyVerdict
  tool: string
  sanitizedArgs: unknown
  transcript: string
}): boolean {
  const { policyVerdict, tool, sanitizedArgs, transcript } = input

  if (policyVerdict.decision === "ask") {
    return true
  }

  if (policyVerdict.decision === "deny" && policyVerdict.denyTier === "soft") {
    return true
  }

  if (policyVerdict.reviewLayer === "read" && policyVerdict.decision !== "allow") {
    return true
  }

  if (
    policyVerdict.decision === "manual" &&
    RISK_RANK[policyVerdict.risk] >= RISK_RANK.high
  ) {
    return true
  }

  if (detectInjectionSignals(transcript, sanitizedArgs)) {
    return true
  }

  if (hasSensitiveReadTarget(tool, sanitizedArgs)) {
    return true
  }

  if (
    policyVerdict.decision === "manual" &&
    tool === "bash" &&
    DANGEROUS_MANUAL_BASH_PATTERNS.some((pattern) => pattern.test(stringifyArgs(sanitizedArgs)))
  ) {
    return true
  }

  return false
}

function stringifyArgs(value: unknown): string {
  if (typeof value === "string") return value
  if (value && typeof value === "object") {
    try {
      return JSON.stringify(value)
    } catch {
      return String(value)
    }
  }
  return String(value ?? "")
}

function hasSensitiveReadTarget(tool: string, sanitizedArgs: unknown): boolean {
  if (!["read", "grep", "glob", "list", "ls"].includes(tool)) {
    return false
  }
  const text = stringifyArgs(sanitizedArgs)
  return SENSITIVE_READ_TARGET_PATTERNS.some((pattern) => pattern.test(text))
}
