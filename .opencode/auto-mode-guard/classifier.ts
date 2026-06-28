import type { PolicyVerdict, RiskLevel } from "./policy"
import { requiresFullClassifierReview } from "./injection-heuristics"
import {
  authorizationScoreToDecision,
  buildAuthorizationGuardianPrompt,
  buildQuickFilterGuardianPrompt,
  extractGuardianReasoning,
  parseGuardianScore,
  quickFilterNeedsFullReview,
} from "./granite-guardian"

export type ClassifierDecision = "allow" | "deny"

export interface SemanticClassifierVerdict {
  permissionDecision: ClassifierDecision
  riskLevel: RiskLevel
  reason: string
  requiredUserClarification?: string
  confidence?: number
  stage?: "quick-filter" | "full-review"
}

export interface SemanticClassificationInput {
  sessionID?: string
  tool: string
  args: Record<string, unknown>
  policyVerdict: PolicyVerdict
}

export interface SemanticClassifierOptions {
  client: any
  directory: string
  worktree?: string
  model?: { providerID: string; modelID: string }
  maxTranscriptMessages?: number
  maxTranscriptChars?: number
  cacheTtlMs?: number
  log?: (
    level: "debug" | "info" | "warn" | "error",
    message: string,
    extra?: Record<string, unknown>,
  ) => Promise<void> | void
}

interface CachedVerdict {
  expiresAt: number
  verdict: SemanticClassifierVerdict
}

const DEFAULT_MAX_TRANSCRIPT_MESSAGES = 10
const DEFAULT_MAX_TRANSCRIPT_CHARS = 16000
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000
const MAX_CACHE_ENTRIES = 128
const MAX_ARGS_CHARS = 9000
const MAX_PART_CHARS = 3000

const GUARDIAN_QUICK_SYSTEM =
  "You are IBM Granite Guardian in no-think scoring mode. Reply only with the required score tags. Do not call tools."
const GUARDIAN_FULL_SYSTEM =
  "You are IBM Granite Guardian judging whether a proposed agent tool call is authorized. Reply only with the required thinking and score tags. Do not call tools."

export function createSemanticClassifier(options: SemanticClassifierOptions) {
  const classifierSessions = new Set<string>()
  const cache = new Map<string, CachedVerdict>()
  const model = options.model
  const maxTranscriptMessages = options.maxTranscriptMessages ?? DEFAULT_MAX_TRANSCRIPT_MESSAGES
  const maxTranscriptChars = options.maxTranscriptChars ?? DEFAULT_MAX_TRANSCRIPT_CHARS
  const cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS

  return {
    isClassifierSession(sessionID?: string): boolean {
      return Boolean(sessionID && classifierSessions.has(sessionID))
    },

    async classify(input: SemanticClassificationInput): Promise<SemanticClassifierVerdict> {
      if (!input.sessionID) {
        return deny("critical", "No session id was available, so explicit user authorization cannot be verified.")
      }

      const sanitizedArgs = sanitizeForClassifier(input.args)
      const now = Date.now()

      let transcript: string
      try {
        transcript = await buildClassifierTranscript(options.client, input.sessionID, {
          maxMessages: maxTranscriptMessages,
          maxChars: maxTranscriptChars,
        })
      } catch (error) {
        await options.log?.("warn", "Could not build transcript for semantic classifier", {
          sessionID: input.sessionID,
          tool: input.tool,
          error: stringifyError(error),
        })
        return deny("critical", "Could not read a classifier transcript to verify user authorization.")
      }

      const cacheKey = buildCacheKey(input, sanitizedArgs, transcript)
      const cached = cache.get(cacheKey)
      if (cached && cached.expiresAt > now) {
        await options.log?.("debug", "Semantic classifier cache hit", {
          sessionID: input.sessionID,
          tool: input.tool,
          decision: cached.verdict.permissionDecision,
        })
        return cached.verdict
      }

      try {
        const directory = options.worktree ?? options.directory
        const mustUseFullReview =
          input.policyVerdict.risk === "critical" ||
          input.policyVerdict.risk === "high" ||
          requiresFullClassifierReview({
            policyVerdict: input.policyVerdict,
            tool: input.tool,
            sanitizedArgs,
            transcript,
          })

        let quickReview = true
        if (!mustUseFullReview) {
          quickReview = await runQuickFilter({
            client: options.client,
            classifierSessions,
            model,
            directory,
            tool: input.tool,
            policyVerdict: input.policyVerdict,
            sanitizedArgs,
            transcript,
          })
        } else {
          await options.log?.("debug", "Skipping quick filter; routing directly to full review", {
            sessionID: input.sessionID,
            tool: input.tool,
            policyRisk: input.policyVerdict.risk,
          })
        }

        if (
          !quickReview &&
          !requiresFullClassifierReview({
            policyVerdict: input.policyVerdict,
            tool: input.tool,
            sanitizedArgs,
            transcript,
          })
        ) {
          const allowed: SemanticClassifierVerdict = {
            permissionDecision: "allow",
            riskLevel: "low",
            reason: "Quick filter cleared this action without needing full review.",
            confidence: 0.9,
            stage: "quick-filter",
          }
          cache.set(cacheKey, { expiresAt: now + cacheTtlMs, verdict: allowed })
          pruneCache(cache)
          return allowed
        }

        const argsJson = truncate(safeJsonStringify(sanitizedArgs), MAX_ARGS_CHARS)
        const prompt = buildAuthorizationGuardianPrompt({
          tool: input.tool,
          policyVerdict: input.policyVerdict,
          sanitizedArgs,
          transcript,
          argsJson,
          directory: options.directory,
          worktree: options.worktree,
          think: input.policyVerdict.risk === "critical" || input.policyVerdict.risk === "high",
        })

        const raw = await runGuardianPrompt({
          client: options.client,
          classifierSessions,
          prompt,
          model,
          directory,
          system: GUARDIAN_FULL_SYSTEM,
        })

        const verdict: SemanticClassifierVerdict = {
          ...normalizeGuardianVerdict(raw, input.policyVerdict),
          stage: "full-review",
        }

        cache.set(cacheKey, { expiresAt: now + cacheTtlMs, verdict })
        pruneCache(cache)

        await options.log?.("info", "Semantic classifier verdict", {
          sessionID: input.sessionID,
          tool: input.tool,
          decision: verdict.permissionDecision,
          risk: verdict.riskLevel,
          confidence: verdict.confidence,
          reason: verdict.reason,
          stage: verdict.stage,
        })

        return verdict
      } catch (error) {
        await options.log?.("error", "Semantic classifier failed closed", {
          sessionID: input.sessionID,
          tool: input.tool,
          error: stringifyError(error),
        })
        return deny("critical", `Semantic classifier failed closed: ${stringifyError(error)}`)
      }
    },
  }
}

export function formatSemanticBlock(
  verdict: SemanticClassifierVerdict,
  policyVerdict: PolicyVerdict,
): string {
  const details = [
    "Auto Mode Guard blocked this tool call after semantic classification.",
    `Classifier decision: ${verdict.permissionDecision}`,
    `Classifier risk: ${verdict.riskLevel}`,
    `Classifier reason: ${verdict.reason}`,
    `Static policy reason: ${policyVerdict.reason}`,
  ]

  if (verdict.stage) {
    details.push(`Classifier stage: ${verdict.stage}`)
  }

  if (policyVerdict.reviewLayer) {
    details.push(`Review layer: ${policyVerdict.reviewLayer}`)
  }

  if (verdict.requiredUserClarification?.trim()) {
    details.push(`Required user clarification: ${verdict.requiredUserClarification.trim()}`)
  }

  if (policyVerdict.normalized) {
    details.push(`Normalized command: ${policyVerdict.normalized}`)
  }

  if (policyVerdict.paths?.length) {
    details.push(`Paths: ${policyVerdict.paths.join(", ")}`)
  }

  return details.join("\n")
}

async function runQuickFilter(options: {
  client: any
  classifierSessions: Set<string>
  model?: { providerID: string; modelID: string }
  directory: string
  tool: string
  policyVerdict: PolicyVerdict
  sanitizedArgs: unknown
  transcript: string
}): Promise<boolean> {
  const argsJson = truncate(safeJsonStringify(options.sanitizedArgs), MAX_ARGS_CHARS)
  const prompt = buildQuickFilterGuardianPrompt({
    tool: options.tool,
    policyVerdict: options.policyVerdict,
    sanitizedArgs: options.sanitizedArgs,
    transcript: options.transcript,
    argsJson,
  })

  const text = await runGuardianPrompt({
    client: options.client,
    classifierSessions: options.classifierSessions,
    prompt,
    model: options.model,
    directory: options.directory,
    system: GUARDIAN_QUICK_SYSTEM,
  })

  const score = parseGuardianScore(text)
  if (!score) {
    return true
  }
  return quickFilterNeedsFullReview(score)
}

async function runGuardianPrompt(options: {
  client: any
  classifierSessions: Set<string>
  prompt: string
  model?: { providerID: string; modelID: string }
  directory: string
  system: string
}): Promise<string> {
  const sessionID = await createClassifierSession(options.client, options.classifierSessions, options.directory)

  try {
    const body: Record<string, unknown> = {
      system: options.system,
      tools: disabledClassifierTools(),
      parts: [{ type: "text", text: options.prompt }],
    }

    if (options.model) {
      body.model = options.model
    }

    const result = await options.client.session.prompt({
      path: { id: sessionID },
      query: { directory: options.directory },
      body,
    })

    const text = extractTextOutput(result)
    if (!text) {
      throw new Error("Granite Guardian returned no text.")
    }

    return text
  } finally {
    try {
      await options.client.session.delete({ path: { id: sessionID } })
    } catch {
      // best effort
    }
    options.classifierSessions.delete(sessionID)
  }
}

function disabledClassifierTools() {
  return {
    bash: false,
    edit: false,
    write: false,
    read: false,
    grep: false,
    glob: false,
    list: false,
    webfetch: false,
    websearch: false,
    task: false,
    todowrite: false,
    lsp: false,
    skill: false,
  }
}

async function createClassifierSession(
  client: any,
  classifierSessions: Set<string>,
  directory: string,
): Promise<string> {
  const created = await client.session.create({
    body: {
      title: `auto-mode-guard-classifier-${new Date().toISOString()}`,
    },
    query: { directory },
  })

  const sessionID = extractSessionID(created)
  if (!sessionID) {
    throw new Error("Could not create a classifier session.")
  }

  classifierSessions.add(sessionID)
  return sessionID
}

async function buildClassifierTranscript(
  client: any,
  sessionID: string,
  options: { maxMessages: number; maxChars: number },
): Promise<string> {
  const response = await client.session.messages({ path: { id: sessionID } })
  const items = extractMessageItems(response)

  const formatted = items
    .flatMap(formatClassifierTranscriptEntries)
    .filter((entry): entry is string => Boolean(entry))
    .slice(-options.maxMessages)

  if (formatted.length === 0) {
    return "[No user messages or prior tool calls were available in the session transcript.]"
  }

  return truncate(formatted.join("\n\n---\n\n"), options.maxChars)
}

function normalizeGuardianVerdict(raw: string, policyVerdict: PolicyVerdict): SemanticClassifierVerdict {
  const score = parseGuardianScore(raw)
  if (!score) {
    return deny(
      policyVerdict.risk === "low" ? "high" : policyVerdict.risk,
      "Granite Guardian returned an unparseable score; failing closed.",
    )
  }

  const permissionDecision = authorizationScoreToDecision(score)
  const reasoning = truncate(redactSecretsInText(extractGuardianReasoning(raw)), 1200)
  const fallbackReason =
    permissionDecision === "allow"
      ? "Granite Guardian authorized this action against explicit user intent."
      : "Granite Guardian denied: the action is not explicitly authorized by user messages."

  if (permissionDecision === "allow") {
    return {
      permissionDecision: "allow",
      riskLevel: "low",
      reason: reasoning || fallbackReason,
      confidence: 0.85,
    }
  }

  const riskLevel: RiskLevel =
    policyVerdict.risk === "low" || policyVerdict.risk === "medium" ? "high" : policyVerdict.risk

  return {
    permissionDecision: "deny",
    riskLevel,
    reason: reasoning || fallbackReason,
    requiredUserClarification:
      "Ask the user for explicit, concrete permission for this exact tool action.",
    confidence: 0.9,
  }
}

function deny(riskLevel: RiskLevel, reason: string): SemanticClassifierVerdict {
  return {
    permissionDecision: "deny",
    riskLevel,
    reason,
    requiredUserClarification: "Ask the user for explicit, concrete permission for this exact tool action.",
    confidence: 1,
  }
}

function extractMessageItems(response: unknown): unknown[] {
  if (Array.isArray(response)) return response
  const value = response as any
  if (Array.isArray(value?.data)) return value.data
  if (Array.isArray(value?.data?.messages)) return value.data.messages
  if (Array.isArray(value?.messages)) return value.messages
  if (Array.isArray(value?.items)) return value.items
  return []
}

function formatClassifierTranscriptEntries(item: unknown): string[] {
  const value = item as any
  const info = value?.info ?? value
  const role = String(info?.role ?? value?.role ?? "").toLowerCase()
  const parts: unknown[] = Array.isArray(value?.parts)
    ? value.parts
    : Array.isArray(info?.parts)
      ? info.parts
      : []

  const entries: string[] = []

  if (role === "user") {
    const text = parts
      .map(extractVisibleTextPart)
      .filter((part): part is string => Boolean(part?.trim()))
      .join("\n")

    const fallback =
      typeof value?.content === "string"
        ? value.content
        : typeof info?.content === "string"
          ? info.content
          : typeof value?.text === "string"
            ? value.text
            : ""

    const sanitized = truncate(redactSecretsInText((text || fallback).trim()), MAX_PART_CHARS)
    if (sanitized) {
      entries.push(`USER:\n${sanitized}`)
    }
  }

  for (const part of parts) {
    const toolCall = formatToolCallPart(part)
    if (toolCall) {
      entries.push(toolCall)
    }
  }

  return entries
}

function formatToolCallPart(part: unknown): string | undefined {
  const value = part as any
  const type = String(value?.type ?? "").toLowerCase()

  if (!type.includes("tool")) {
    return undefined
  }

  const tool = String(value?.tool ?? value?.name ?? value?.toolName ?? "unknown")
  const args = sanitizeForClassifier(value?.args ?? value?.input ?? value?.arguments ?? value?.state?.input ?? {})
  return `TOOL_CALL: ${tool}\n${truncate(safeJsonStringify(args), MAX_PART_CHARS)}`
}

function extractVisibleTextPart(part: unknown): string | undefined {
  const value = part as any
  const type = String(value?.type ?? "").toLowerCase()

  if (
    type.includes("reason") ||
    type.includes("thought") ||
    type.includes("tool") ||
    type.includes("patch") ||
    type.includes("diff") ||
    type.includes("file") ||
    type.includes("output")
  ) {
    return undefined
  }

  if (type && type !== "text" && type !== "message") {
    return undefined
  }

  if (typeof value?.text === "string") return value.text
  if (typeof value?.content === "string") return value.content
  return undefined
}

function sanitizeForClassifier(value: unknown, key = "", depth = 0): unknown {
  if (depth > 6) return "[TRUNCATED_DEPTH]"

  if (isSensitiveKey(key)) {
    return "[REDACTED]"
  }

  if (typeof value === "string") {
    return truncate(redactSecretsInText(value), 3000)
  }

  if (typeof value === "number" || typeof value === "boolean" || value === null || value === undefined) {
    return value
  }

  if (Array.isArray(value)) {
    return value.slice(0, 50).map((item) => sanitizeForClassifier(item, key, depth + 1))
  }

  if (typeof value === "object") {
    const output: Record<string, unknown> = {}
    for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>).slice(0, 80)) {
      output[childKey] = sanitizeForClassifier(childValue, childKey, depth + 1)
    }
    return output
  }

  return String(value)
}

function isSensitiveKey(key: string): boolean {
  return /(secret|token|password|passwd|pwd|api[-_]?key|private[-_]?key|credential|cookie|authorization|auth|session)/i.test(key)
}

function redactSecretsInText(text: string): string {
  return text
    .replace(/((?:api[-_]?key|token|password|passwd|secret|credential|authorization|cookie)\s*[:=]\s*)([^\s'"`,;]+)/gi, "$1[REDACTED]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]")
    .replace(/\b(?:sk|pk|rk|ghp|gho|github_pat|xoxb|xoxp)_[A-Za-z0-9_\-]{12,}\b/g, "[REDACTED_TOKEN]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_ACCESS_KEY]")
}

function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return JSON.stringify(String(value))
  }
}

function buildCacheKey(
  input: SemanticClassificationInput,
  sanitizedArgs: unknown,
  transcript: string,
): string {
  return [
    input.sessionID ?? "no-session",
    input.tool,
    input.policyVerdict.reason,
    input.policyVerdict.reviewLayer ?? "action",
    input.policyVerdict.normalized ?? "",
    input.policyVerdict.paths?.join(",") ?? "",
    truncate(safeJsonStringify(sanitizedArgs), 2000),
    truncate(transcript, 2000),
  ].join("\u0000")
}

function pruneCache(cache: Map<string, CachedVerdict>) {
  const now = Date.now()
  for (const [key, value] of cache) {
    if (value.expiresAt <= now) {
      cache.delete(key)
    }
  }

  while (cache.size > MAX_CACHE_ENTRIES) {
    const first = cache.keys().next().value
    if (!first) return
    cache.delete(first)
  }
}

function extractTextOutput(result: unknown): string | undefined {
  const value = result as any
  const parts = Array.isArray(value?.data?.parts)
    ? value.data.parts
    : Array.isArray(value?.parts)
      ? value.parts
      : []

  const fromParts = parts
    .map((part: any) => (typeof part?.text === "string" ? part.text : typeof part?.content === "string" ? part.content : ""))
    .filter(Boolean)
    .join("\n")

  return (
    fromParts ||
    (typeof value?.data?.text === "string" ? value.data.text : undefined) ||
    (typeof value?.text === "string" ? value.text : undefined) ||
    (typeof value?.data?.info?.text === "string" ? value.data.info.text : undefined)
  )
}

function extractSessionID(value: unknown): string | undefined {
  const item = value as any
  const candidates = [
    item?.id,
    item?.sessionID,
    item?.sessionId,
    item?.data?.id,
    item?.data?.sessionID,
    item?.data?.sessionId,
    item?.data?.info?.id,
    item?.info?.id,
  ]

  return candidates.find((candidate) => typeof candidate === "string" && candidate.length > 0)
}

function truncate(value: string, maxChars: number): string {
  if (value.length <= maxChars) return value
  return `${value.slice(0, maxChars)}\n... truncated by Auto Mode Guard ...`
}

function stringifyError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`
  }
  return String(error)
}
