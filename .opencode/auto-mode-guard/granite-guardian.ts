import type { PolicyVerdict } from "./policy"

/** Default local Ollama tag — `ollama pull granite4.1-guardian:8b` */
export const DEFAULT_GRANITE_GUARDIAN_MODEL = "ollama/granite4.1-guardian:8b"

const THINK_OPEN = "<think>"
const THINK_CLOSE = "</think>"

const GUARDIAN_JUDGE_THINK =
  `${THINK_OPEN}As a judge agent, carefully analyze whether the provided text meets the ` +
  "given judging criteria. Use all available information, including conversations, " +
  "documents, and tools. Reason through the evidence step by step before providing " +
  `your score. Wrap your reasoning in ${THINK_OPEN}${THINK_CLOSE} tags, then provide your ` +
  "score in <score></score> tags."

const GUARDIAN_JUDGE_NOTHINK =
  "<no-think>As a judge agent, assess whether the provided text meets the given " +
  "judging criteria using all available information, including conversations, " +
  "documents, and tools. Provide your score immediately without explanation. " +
  `Output empty ${THINK_OPEN}\\n${THINK_CLOSE} tags followed by your score in <score></score> tags.`

export const QUICK_FILTER_CRITERIA =
  "The proposed autonomous agent tool call requires full security review before execution. " +
  "This includes secrets, credentials, CI/CD, deployment, infrastructure, remotes, databases, " +
  "destructive operations, reads outside trust boundaries, or any action where explicit user " +
  "authorization in the conversation is absent or ambiguous."

export const AUTHORIZATION_CRITERIA =
  "The proposed tool call is explicitly authorized by the user's recent visible instructions " +
  "in the conversation transcript. User messages define authorization; assistant plans do not. " +
  "The action must be clearly within the user's explicit request with bounded blast radius. " +
  'Vague requests such as "clean up", "fix deploy", "optimize", or "make it work" do not ' +
  "authorize secrets, CI/CD, deployment, production, database, remote, cloud, destructive, " +
  "or cross-workspace actions."

export const FUNCTION_CALL_HALLUCINATION_CRITERIA =
  "Function call hallucination occurs when a proposed tool call does not adhere to the correct " +
  "format for the tool or is inconsistent with the user's requirements. This includes incorrect " +
  "argument names, values, types, calling unavailable tools, or actions beyond explicit user authorization."

export function isGraniteGuardianModel(model?: { providerID: string; modelID: string }): boolean {
  if (!model) return false
  const ref = `${model.providerID}/${model.modelID}`.toLowerCase()
  return ref.includes("granite") && ref.includes("guardian")
}

export function buildGuardianBlock(criteria: string, think: boolean): string {
  const judgeInstruction = think ? GUARDIAN_JUDGE_THINK : GUARDIAN_JUDGE_NOTHINK
  return (
    `<guardian>${judgeInstruction}\n\n` +
    `### Criteria: ${criteria}\n\n` +
    "### Scoring Schema: If the last assistant's text meets the criteria, return 'yes'; otherwise, return 'no'."
  )
}

export function buildGuardianGenerationPrefix(think: boolean): string {
  return think ? `${THINK_OPEN}\n` : `${THINK_OPEN}\n${THINK_CLOSE}\n`
}

export function buildQuickFilterGuardianPrompt(input: {
  tool: string
  policyVerdict: PolicyVerdict
  sanitizedArgs: unknown
  transcript: string
  argsJson: string
}): string {
  const assistantBody = buildProposedActionAssistantText(input)
  return [
    "Conversation and prior tool context:",
    input.transcript,
    "",
    assistantBody,
    "",
    buildGuardianBlock(QUICK_FILTER_CRITERIA, false),
    "",
    buildGuardianGenerationPrefix(false),
  ].join("\n")
}

export function buildAuthorizationGuardianPrompt(input: {
  tool: string
  policyVerdict: PolicyVerdict
  sanitizedArgs: unknown
  transcript: string
  argsJson: string
  directory: string
  worktree?: string
  think: boolean
}): string {
  const layer = input.policyVerdict.reviewLayer ?? "action"
  const layerNote =
    layer === "read"
      ? "This is a read-layer review: decide whether reading or fetching this content is explicitly authorized."
      : "This is an action-layer review: decide whether executing this tool call is explicitly authorized."

  const pathInfo = [
    `Project directory: ${input.directory}`,
    input.worktree ? `Git worktree: ${input.worktree}` : undefined,
  ]
    .filter(Boolean)
    .join("\n")

  const assistantBody = buildProposedActionAssistantText(input)
  const criteria = `${AUTHORIZATION_CRITERIA} ${layerNote}`

  return [
    pathInfo,
    "",
    "Conversation and prior tool context (user messages and prior tool calls only):",
    input.transcript,
    "",
    "Static policy pre-verdict:",
    `- decision: ${input.policyVerdict.decision}`,
    `- risk: ${input.policyVerdict.risk}`,
    `- mutates: ${input.policyVerdict.mutates}`,
    `- reason: ${input.policyVerdict.reason}`,
    input.policyVerdict.normalized ? `- normalized command: ${input.policyVerdict.normalized}` : undefined,
    input.policyVerdict.paths?.length ? `- paths: ${input.policyVerdict.paths.join(", ")}` : undefined,
    "",
    assistantBody,
    "",
    buildGuardianBlock(criteria, input.think),
    "",
    buildGuardianGenerationPrefix(input.think),
  ]
    .filter((line): line is string => line !== undefined)
    .join("\n")
}

function buildProposedActionAssistantText(input: {
  tool: string
  policyVerdict: PolicyVerdict
  sanitizedArgs: unknown
  argsJson: string
}): string {
  return [
    "ASSISTANT (proposed tool call to judge):",
    `tool: ${input.tool}`,
    "sanitized args:",
    input.argsJson,
    "",
    "Static policy:",
    `- decision: ${input.policyVerdict.decision}`,
    `- reason: ${input.policyVerdict.reason}`,
  ].join("\n")
}

export function parseGuardianScore(text: string): "yes" | "no" | undefined {
  const scoreTags = [...text.matchAll(/<score>\s*(yes|no)\s*<\/score>/gi)]
  if (scoreTags.length > 0) {
    return scoreTags[scoreTags.length - 1]![1]!.toLowerCase() as "yes" | "no"
  }

  const trimmed = text.trim().toLowerCase()
  if (/^yes\b/.test(trimmed) || /\byes\s*$/i.test(trimmed)) return "yes"
  if (/^no\b/.test(trimmed) || /\bno\s*$/i.test(trimmed)) return "no"

  const lastWord = trimmed.split(/\s+/).pop()
  if (lastWord === "yes" || lastWord === "no") {
    return lastWord
  }

  return undefined
}

export function extractGuardianReasoning(text: string): string {
  const pattern = new RegExp(`${THINK_OPEN}([\\s\\S]*?)${THINK_CLOSE}`, "gi")
  const matches = [...text.matchAll(pattern)]
  for (let i = matches.length - 1; i >= 0; i -= 1) {
    const body = matches[i]![1]!.trim()
    if (body) {
      return body
    }
  }
  return ""
}

export function quickFilterNeedsFullReview(score: "yes" | "no"): boolean {
  return score === "yes"
}

export function authorizationScoreToDecision(score: "yes" | "no"): "allow" | "deny" {
  return score === "yes" ? "allow" : "deny"
}
