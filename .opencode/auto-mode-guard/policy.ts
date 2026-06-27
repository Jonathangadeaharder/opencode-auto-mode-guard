import { promises as fs } from "node:fs"
import * as path from "node:path"
import type { AutoModeGuardConfig } from "./config"
import { matchesAnyPattern } from "./config"
import type { OpenCodePermissionVerdict } from "./permissions"

export type PolicyDecision = "allow" | "deny" | "manual" | "ask"
export type RiskLevel = "low" | "medium" | "high" | "critical"
export type DenyTier = "hard" | "soft"
export type ReviewLayer = "read" | "action"

export interface PolicyInput {
  tool: string
  args: Record<string, unknown>
  directory: string
  worktree?: string
  config: AutoModeGuardConfig
  openCodePermission?: OpenCodePermissionVerdict
}

export interface PolicyVerdict {
  decision: PolicyDecision
  risk: RiskLevel
  mutates: boolean
  reason: string
  normalized?: string
  paths?: string[]
  denyTier?: DenyTier
  reviewLayer?: ReviewLayer
}

export const MUTATION_TOOLS = new Set([
  "edit",
  "write",
  "patch",
  "apply_patch",
  "replace_content",
  "replace_symbol_body",
  "insert_after_symbol",
  "insert_before_symbol",
  "create_text_file",
  "delete_file",
  "move_file",
  "rename_file",
])

const READ_TOOLS = new Set([
  "read",
  "grep",
  "glob",
  "list",
  "ls",
  "find",
  "search",
  "view",
])

const WEB_TOOLS = new Set(["webfetch", "websearch"])

const ALWAYS_HARD_DENY_BASH = [
  /(^|[;&|()\s])sudo\b/i,
  /(^|[;&|()\s])su\b/i,
  /(^|[;&|()\s])chmod\s+-R\s+777\b/i,
  /(^|[;&|()\s])chown\s+-R\b/i,
  /(^|[;&|()\s])mkfs\b/i,
  /(^|[;&|()\s])dd\b[^;&|]*\bof=\/dev\//i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:/,
  /(^|[;&|()\s])rm\s+-[^;&|]*[rf][^;&|]*\s+(\/|\.\.?(\/|$)|~)(\s|$)/i,
  /(curl|wget)[^;&|]*(\||>)\s*(sh|bash|zsh|fish)\b/i,
  /bash\s+<\s*\(\s*(curl|wget)\b/i,
]

const ALWAYS_SOFT_MANUAL_BASH = [
  /(^|[;&|()\s])git\s+push\b/i,
  /(^|[;&|()\s])git\s+reset\s+--hard\b/i,
  /(^|[;&|()\s])git\s+clean\s+-[^;&|]*[fd]/i,
  /(^|[;&|()\s])git\s+branch\s+-D\b/i,
  /(^|[;&|()\s])git\s+tag\s+-d\b/i,
  /(^|[;&|()\s])gh\s+(workflow|run|api)\b/i,
  /(^|[;&|()\s])kubectl\b/i,
  /(^|[;&|()\s])helm\b/i,
  /(^|[;&|()\s])terraform\s+(apply|destroy|import|state|taint|untaint)\b/i,
  /(^|[;&|()\s])(aws|gcloud|az)\b/i,
  /(^|[;&|()\s])(ssh|scp|rsync)\b/i,
  /(^|[;&|()\s])(psql|mysql|redis-cli|mongosh)\b/i,
  /(^|[;&|()\s])docker\s+(compose\s+)?(down|rm|rmi|prune|system\s+prune|volume\s+rm)\b/i,
]

const SAFE_BASH = [
  /^\s*pwd\s*$/i,
  /^\s*ls(\s+[-\w@.=/,:+]+)*\s*$/i,
  /^\s*git\s+(status|diff|log|show|branch)(\b|\s)/i,
  /^\s*(rg|grep)(\s|$)/i,
  /^\s*find\s+[^;&|]*$/i,
  /^\s*cat\s+[^;&|]*$/i,
  /^\s*(head|tail|wc)\s+[^;&|]*$/i,
  /^\s*(pnpm|npm|yarn|bun)\s+(run\s+)?(test|typecheck|lint|check)(\b|\s)/i,
  /^\s*(cargo|go)\s+test(\b|\s)/i,
  /^\s*pytest(\b|\s)/i,
  /^\s*(pnpm\s+exec|npx|bunx)\s+tsc\s+--noEmit(\b|\s)/i,
  /^\s*(pnpm\s+exec|npx|bunx)\s+biome\s+check(\b|\s)/i,
  /^\s*(pnpm\s+exec|npx|bunx)\s+eslint(\b|\s)/i,
  /^\s*(pnpm\s+exec|npx|bunx)\s+prettier\s+--check(\b|\s)/i,
]

const BASH_MUTATION_HINTS = [
  /(^|[;&|()\s])(rm|mv|cp|touch|mkdir|rmdir|install)\b/i,
  />|>>|\btee\b/i,
  /(^|[;&|()\s])git\s+(commit|merge|rebase|checkout|switch|restore|stash|pull|fetch)\b/i,
  /(^|[;&|()\s])(pnpm|npm|yarn|bun)\s+(install|add|remove|update|upgrade|dedupe)\b/i,
  /(--write|--fix|--fix-dry-run)\b/i,
]

export function isMutationTool(tool: string): boolean {
  return MUTATION_TOOLS.has(tool)
}

export function isReadLayerTool(tool: string): boolean {
  return READ_TOOLS.has(tool) || WEB_TOOLS.has(tool)
}

export function requiresClassifier(verdict: PolicyVerdict): boolean {
  if (verdict.decision === "manual") return true
  if (verdict.decision === "deny" && verdict.denyTier === "soft") return true
  if (verdict.reviewLayer === "read" && verdict.decision !== "allow") return true
  return false
}

export async function evaluateToolCall(input: PolicyInput): Promise<PolicyVerdict> {
  const openCode = input.openCodePermission
  if (openCode?.action === "allow") {
    return {
      decision: "allow",
      risk: "low",
      mutates: isMutationTool(input.tool) || input.tool === "bash",
      reason: openCode.reason,
    }
  }

  if (openCode?.action === "deny") {
    return hardDeny(openCode.reason, {
      mutates: isMutationTool(input.tool) || input.tool === "bash",
      risk: "high",
    })
  }

  if (openCode?.action === "ask") {
    return {
      decision: "ask",
      risk: "medium",
      mutates: isMutationTool(input.tool) || input.tool === "bash",
      reason: openCode.reason,
      reviewLayer: isReadLayerTool(input.tool) ? "read" : "action",
    }
  }

  if (matchesAnyPattern(input.config.ask.tools, input.tool)) {
    return {
      decision: "ask",
      risk: "medium",
      mutates: false,
      reason: `Tool '${input.tool}' is configured to require explicit user approval`,
      reviewLayer: isReadLayerTool(input.tool) ? "read" : "action",
    }
  }

  const tool = input.tool
  const args = input.args ?? {}
  const root = path.resolve(input.worktree || input.directory)

  if (WEB_TOOLS.has(tool)) {
    return evaluateWebTool(args, tool, input.config)
  }

  if (MUTATION_TOOLS.has(tool)) {
    return evaluateFileMutation(args, root, tool)
  }

  if (READ_TOOLS.has(tool)) {
    return evaluateFileRead(args, root, tool)
  }

  if (tool === "bash") {
    return evaluateBash(args, input.config)
  }

  return {
    decision: "manual",
    risk: "medium",
    mutates: true,
    reason: `Unknown tool '${tool}' requires semantic review`,
    reviewLayer: "action",
  }
}

async function evaluateFileMutation(
  args: Record<string, unknown>,
  root: string,
  tool: string,
): Promise<PolicyVerdict> {
  const rawPaths = extractCandidatePaths(args)

  if (rawPaths.length === 0) {
    return softManual(`Mutation tool '${tool}' did not expose a target path`, true)
  }

  const resolved = await Promise.all(rawPaths.map((candidate) => resolveInsideRoot(root, candidate)))
  const escaped = resolved.find((item) => !item.insideRoot)
  if (escaped) {
    return hardDeny(`Blocked workspace escape through '${escaped.inputPath}'`, {
      mutates: true,
      risk: "critical",
      paths: resolved.map((item) => item.displayPath),
    })
  }

  const sensitive = resolved.find((item) => isSensitivePath(item.relativePath))
  if (sensitive) {
    if (isSecretPath(sensitive.relativePath)) {
      return hardDeny(`Mutation targets protected secret path '${sensitive.relativePath}'`, {
        mutates: true,
        risk: "critical",
        paths: resolved.map((item) => item.displayPath),
      })
    }

    return softManual(`Mutation targets protected path '${sensitive.relativePath}'`, true, {
      risk: "high",
      paths: resolved.map((item) => item.displayPath),
    })
  }

  return {
    decision: "allow",
    risk: "low",
    mutates: true,
    paths: resolved.map((item) => item.displayPath),
    reason: `Allowed code mutation with target inside workspace via '${tool}'`,
    reviewLayer: "action",
  }
}

async function evaluateFileRead(
  args: Record<string, unknown>,
  root: string,
  tool: string,
): Promise<PolicyVerdict> {
  const rawPaths = extractCandidatePaths(args)

  if (rawPaths.length === 0) {
    return {
      decision: "allow",
      risk: "low",
      mutates: false,
      reason: `Allowed read-only tool '${tool}' without explicit path`,
      reviewLayer: "read",
    }
  }

  const resolved = await Promise.all(rawPaths.map((candidate) => resolveInsideRoot(root, candidate)))
  const escaped = resolved.find((item) => !item.insideRoot)
  if (escaped) {
    return {
      decision: "manual",
      risk: "high",
      mutates: false,
      paths: resolved.map((item) => item.displayPath),
      reason: `Read outside workspace requires semantic review: '${escaped.inputPath}'`,
      reviewLayer: "read",
    }
  }

  const secret = resolved.find((item) => isSecretPath(item.relativePath))
  if (secret) {
    return hardDeny(`Blocked read of secret-like path '${secret.relativePath}'`, {
      mutates: false,
      risk: "critical",
      paths: resolved.map((item) => item.displayPath),
      reviewLayer: "read",
    })
  }

  const suspicious = resolved.find((item) => isSensitivePath(item.relativePath))
  if (suspicious) {
    return {
      decision: "manual",
      risk: "medium",
      mutates: false,
      paths: resolved.map((item) => item.displayPath),
      reason: `Read of sensitive project file '${suspicious.relativePath}' requires read-layer review`,
      reviewLayer: "read",
    }
  }

  return {
    decision: "allow",
    risk: "low",
    mutates: false,
    paths: resolved.map((item) => item.displayPath),
    reason: `Allowed read-only tool '${tool}'`,
    reviewLayer: "read",
  }
}

function evaluateWebTool(
  args: Record<string, unknown>,
  tool: string,
  config: AutoModeGuardConfig,
): PolicyVerdict {
  const target = String(args.url ?? args.query ?? args.target ?? "").trim()
  if (!target) {
    return {
      decision: "manual",
      risk: "medium",
      mutates: false,
      reason: `${tool} without an explicit target requires read-layer review`,
      reviewLayer: "read",
    }
  }

  if (isTrustedDomain(target, config.environment.domains)) {
    return {
      decision: "allow",
      risk: "low",
      mutates: false,
      reason: `${tool} target matches trusted environment domain`,
      reviewLayer: "read",
    }
  }

  return {
    decision: "manual",
    risk: "high",
    mutates: false,
    reason: `${tool} target '${target}' requires read-layer review`,
    reviewLayer: "read",
  }
}

function evaluateBash(args: Record<string, unknown>, config: AutoModeGuardConfig): PolicyVerdict {
  const raw = String(args.command ?? args.cmd ?? "")
  const normalized = normalizeCommand(raw)
  const lower = normalized.toLowerCase()

  if (!normalized) {
    return {
      decision: "allow",
      risk: "low",
      mutates: false,
      normalized,
      reason: "Empty bash command has no effect",
      reviewLayer: "action",
    }
  }

  if (matchesAnyPattern(config.ask.bash, normalized)) {
    return {
      decision: "ask",
      risk: "medium",
      mutates: likelyMutates(normalized),
      normalized,
      reason: "Bash command matches configured ask rule",
      reviewLayer: "action",
    }
  }

  if (ALWAYS_HARD_DENY_BASH.some((pattern) => pattern.test(normalized))) {
    return hardDeny("Bash command matches a destructive hard-deny rule", {
      mutates: true,
      risk: "critical",
      normalized,
    })
  }

  if (containsSecretReference(lower)) {
    return hardDeny("Bash command references secret-like files or variables", {
      mutates: false,
      risk: "critical",
      normalized,
    })
  }

  if (
    /(^|[;&|()\s])git\s+push\b/i.test(normalized) &&
    /(--delete|--force|\s-[f]\b)/i.test(normalized)
  ) {
    return softManual("Git push with destructive or force flags requires semantic review", likelyMutates(normalized), {
      risk: "high",
      normalized,
    })
  }

  if (/(^|[;&|()\s])git\s+push\b/i.test(normalized) && isTrustedGitPush(normalized, config.environment.gitRemotes)) {
    return {
      decision: "allow",
      risk: "low",
      mutates: true,
      normalized,
      reason: "Git push matches trusted remote configuration",
      reviewLayer: "action",
    }
  }

  if (ALWAYS_SOFT_MANUAL_BASH.some((pattern) => pattern.test(normalized))) {
    return softManual("Bash command can affect remote, infrastructure, database, or VCS state", likelyMutates(normalized), {
      risk: "high",
      normalized,
    })
  }

  if (hasShellEvasion(normalized)) {
    return softManual("Bash command contains shell constructs that require semantic review", likelyMutates(normalized), {
      risk: "high",
      normalized,
    })
  }

  if (SAFE_BASH.some((pattern) => pattern.test(normalized)) && !dangerousFind(normalized)) {
    return {
      decision: "allow",
      risk: "low",
      mutates: likelyMutates(normalized),
      normalized,
      reason: "Bash command matches static safe-list",
      reviewLayer: "action",
    }
  }

  return softManual("Bash command is not in the static safe-list and needs semantic review", likelyMutates(normalized), {
    risk: likelyMutates(normalized) ? "medium" : "low",
    normalized,
  })
}

export function normalizeCommand(raw: string): string {
  return raw
    .replace(/\$\{IFS\}/g, " ")
    .replace(/\$IFS/g, " ")
    .replace(/\$'\\x20'/g, " ")
    .replace(/\$'\\040'/g, " ")
    .replace(/\\\n/g, " ")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
}

export function formatPolicyBlock(verdict: PolicyVerdict): string {
  const action =
    verdict.decision === "deny"
      ? "blocked"
      : verdict.decision === "ask"
        ? "requires explicit user approval"
        : "requires semantic review"

  const details = [
    `Auto Mode Guard ${action} this tool call.`,
    `Risk: ${verdict.risk}`,
    `Reason: ${verdict.reason}`,
  ]

  if (verdict.denyTier) {
    details.push(`Deny tier: ${verdict.denyTier}`)
  }

  if (verdict.reviewLayer) {
    details.push(`Review layer: ${verdict.reviewLayer}`)
  }

  if (verdict.normalized) {
    details.push(`Normalized command: ${verdict.normalized}`)
  }

  if (verdict.paths?.length) {
    details.push(`Paths: ${verdict.paths.join(", ")}`)
  }

  return details.join("\n")
}

function hardDeny(
  reason: string,
  options: {
    mutates: boolean
    risk: RiskLevel
    normalized?: string
    paths?: string[]
    reviewLayer?: ReviewLayer
  },
): PolicyVerdict {
  return {
    decision: "deny",
    denyTier: "hard",
    risk: options.risk,
    mutates: options.mutates,
    reason,
    normalized: options.normalized,
    paths: options.paths,
    reviewLayer: options.reviewLayer ?? "action",
  }
}

function softManual(
  reason: string,
  mutates: boolean,
  options: { risk?: RiskLevel; normalized?: string; paths?: string[] } = {},
): PolicyVerdict {
  return {
    decision: "manual",
    risk: options.risk ?? "medium",
    mutates,
    reason,
    normalized: options.normalized,
    paths: options.paths,
    reviewLayer: "action",
  }
}

function extractCandidatePaths(args: Record<string, unknown>): string[] {
  const keys = [
    "filePath",
    "filepath",
    "path",
    "targetPath",
    "target",
    "sourcePath",
    "source",
    "destinationPath",
    "destination",
  ]

  const result: string[] = []
  for (const key of keys) {
    const value = args[key]
    if (typeof value === "string" && value.trim()) {
      result.push(value.trim())
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === "string" && item.trim()) {
          result.push(item.trim())
        }
      }
    }
  }

  const files = args.files
  if (Array.isArray(files)) {
    for (const item of files) {
      if (typeof item === "string" && item.trim()) {
        result.push(item.trim())
      } else if (item && typeof item === "object") {
        const maybePath = (item as Record<string, unknown>).path ?? (item as Record<string, unknown>).filePath
        if (typeof maybePath === "string" && maybePath.trim()) {
          result.push(maybePath.trim())
        }
      }
    }
  }

  const patchText = args.patchText ?? args.patch
  if (typeof patchText === "string" && patchText.trim()) {
    result.push(...extractPatchPaths(patchText))
  }

  return [...new Set(result)]
}

export function extractPatchPaths(patchText: string): string[] {
  const paths: string[] = []

  for (const match of patchText.matchAll(/^\*\*\*\s+(?:Update|Add|Delete)\s+File:\s+(.+)$/gim)) {
    paths.push(match[1].trim())
  }

  for (const match of patchText.matchAll(/^(?:---|\+\+\+)\s+(?:a\/|b\/)?(.+)$/gim)) {
    const candidate = match[1].trim()
    if (candidate !== "/dev/null" && candidate !== "dev/null") {
      paths.push(candidate)
    }
  }

  return [...new Set(paths)]
}

async function resolveInsideRoot(root: string, inputPath: string) {
  const absolute = path.resolve(root, inputPath)
  const rootReal = await safeRealpath(root)
  const targetReal = await realpathForExistingTarget(absolute)
  const relativePath = toPosix(path.relative(rootReal, targetReal))
  const insideRoot = isInside(rootReal, targetReal)

  return {
    inputPath,
    absolute,
    realPath: targetReal,
    relativePath: relativePath || path.basename(targetReal),
    insideRoot,
    displayPath: insideRoot ? relativePath || "." : targetReal,
  }
}

async function realpathForExistingTarget(absolute: string): Promise<string> {
  try {
    return await fs.realpath(absolute)
  } catch {
    const parent = path.dirname(absolute)
    const parentReal = await safeRealpath(parent)
    return path.join(parentReal, path.basename(absolute))
  }
}

async function safeRealpath(candidate: string): Promise<string> {
  try {
    return await fs.realpath(candidate)
  } catch {
    return path.resolve(candidate)
  }
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate)
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

function toPosix(value: string): string {
  return value.split(path.sep).join("/")
}

function isSensitivePath(relativePath: string): boolean {
  const normalized = toPosix(relativePath).toLowerCase()
  const base = path.posix.basename(normalized)

  if (isSecretPath(normalized)) {
    return true
  }

  return (
    normalized.startsWith(".github/workflows/") ||
    normalized === ".github/workflows" ||
    normalized.startsWith(".git/hooks/") ||
    normalized === "opencode.json" ||
    normalized.endsWith("/opencode.json") ||
    base === "dockerfile" ||
    base.startsWith("dockerfile.") ||
    base.startsWith("docker-compose") ||
    base === "compose.yml" ||
    base === "compose.yaml" ||
    normalized.startsWith("k8s/") ||
    normalized.startsWith("kubernetes/") ||
    normalized.startsWith("helm/") ||
    normalized.startsWith("charts/") ||
    normalized.startsWith("terraform/") ||
    normalized.startsWith("infra/") ||
    normalized.includes("/migrations/") ||
    base.includes("deploy") ||
    base.includes("release")
  )
}

function isSecretPath(relativePath: string): boolean {
  const normalized = toPosix(relativePath).toLowerCase()
  const base = path.posix.basename(normalized)

  return (
    base === ".env" ||
    base.startsWith(".env.") ||
    base.endsWith(".pem") ||
    base.endsWith(".key") ||
    base === "id_rsa" ||
    base === "id_dsa" ||
    base === "id_ed25519" ||
    normalized.includes("secret") ||
    normalized.includes("credential") ||
    normalized.includes("private-key") ||
    normalized.includes("private_key")
  )
}

function containsSecretReference(lowerCommand: string): boolean {
  return (
    /(^|[\s/])\.env(\.|\s|$)/.test(lowerCommand) ||
    lowerCommand.includes("private-key") ||
    lowerCommand.includes("private_key") ||
    lowerCommand.includes("credential") ||
    lowerCommand.includes("secret") ||
    /\b(id_rsa|id_dsa|id_ed25519)\b/.test(lowerCommand)
  )
}

function hasShellEvasion(normalized: string): boolean {
  return (
    /[`$]\(/.test(normalized) ||
    /\b(eval|exec)\b/.test(normalized) ||
    /;|&&|\|\||\|/.test(normalized) ||
    /\.\.\//.test(normalized) ||
    /<\s*\(/.test(normalized)
  )
}

function likelyMutates(normalized: string): boolean {
  return BASH_MUTATION_HINTS.some((pattern) => pattern.test(normalized))
}

function dangerousFind(normalized: string): boolean {
  return /(^|\s)find\s+/.test(normalized) && /(-delete|-exec\s+rm\b)/.test(normalized)
}

function isTrustedGitPush(normalized: string, trustedRemotes: string[]): boolean {
  if (trustedRemotes.length === 0) return false

  const remoteMatch = normalized.match(/\bgit\s+push\s+([^\s]+)/i)
  const remote = remoteMatch?.[1]
  if (!remote) return false

  return matchesAnyPattern(trustedRemotes, remote)
}

function isTrustedDomain(target: string, trustedDomains: string[]): boolean {
  if (trustedDomains.length === 0) return false

  try {
    const hostname = new URL(target).hostname.toLowerCase()
    return matchesAnyPattern(trustedDomains, hostname)
  } catch {
    return matchesAnyPattern(trustedDomains, target.toLowerCase())
  }
}
