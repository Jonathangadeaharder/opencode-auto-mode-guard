import { promises as fs } from "node:fs"
import * as path from "node:path"

export interface EnvironmentTrust {
  gitRemotes: string[]
  domains: string[]
}

export interface AutoModeGuardConfig {
  environment: EnvironmentTrust
  ask: {
    bash: string[]
    tools: string[]
  }
  escalation: {
    consecutiveBlocks: number
    totalBlocks: number
  }
}

const DEFAULT_CONFIG: AutoModeGuardConfig = {
  environment: {
    gitRemotes: [],
    domains: [],
  },
  ask: {
    bash: [],
    tools: ["webfetch", "websearch"],
  },
  escalation: {
    consecutiveBlocks: 3,
    totalBlocks: 20,
  },
}

const CONFIG_CANDIDATES = [
  ".opencode/auto-mode-guard.json",
  ".opencode/auto-mode-guard/config.json",
]

export async function loadAutoModeGuardConfig(root: string): Promise<AutoModeGuardConfig> {
  const merged: AutoModeGuardConfig = structuredClone(DEFAULT_CONFIG)

  for (const relative of CONFIG_CANDIDATES) {
    const filePath = path.join(root, relative)
    const fromFile = await readJsonFile(filePath)
    if (fromFile) {
      mergeConfig(merged, fromFile)
    }
  }

  const opencode = await readJsonFile(path.join(root, "opencode.json"))
  const opencodeDot = await readJsonFile(path.join(root, ".opencode/opencode.json"))
  for (const source of [opencode, opencodeDot]) {
    const section = source?.autoModeGuard ?? source?.["auto-mode-guard"]
    if (section && typeof section === "object") {
      mergeConfig(merged, section as Record<string, unknown>)
    }
  }

  mergeEnvTrust(merged)
  return merged
}

export function matchesPattern(pattern: string, value: string): boolean {
  const normalizedPattern = pattern.trim().toLowerCase()
  const normalizedValue = value.trim().toLowerCase()
  if (!normalizedPattern || !normalizedValue) return false
  if (normalizedPattern === "*") return true

  const escaped = normalizedPattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".")

  return new RegExp(`^${escaped}$`).test(normalizedValue)
}

export function matchesAnyPattern(patterns: string[], value: string): boolean {
  return patterns.some((pattern) => matchesPattern(pattern, value))
}

function mergeConfig(target: AutoModeGuardConfig, source: Record<string, unknown>) {
  const environment = source.environment
  if (environment && typeof environment === "object") {
    const env = environment as Record<string, unknown>
    if (Array.isArray(env.gitRemotes)) {
      target.environment.gitRemotes.push(...env.gitRemotes.filter((item) => typeof item === "string"))
    }
    if (Array.isArray(env.domains)) {
      target.environment.domains.push(...env.domains.filter((item) => typeof item === "string"))
    }
  }

  const ask = source.ask
  if (ask && typeof ask === "object") {
    const askConfig = ask as Record<string, unknown>
    if (Array.isArray(askConfig.bash)) {
      target.ask.bash.push(...askConfig.bash.filter((item) => typeof item === "string"))
    }
    if (Array.isArray(askConfig.tools)) {
      target.ask.tools.push(...askConfig.tools.filter((item) => typeof item === "string"))
    }
  }

  const escalation = source.escalation
  if (escalation && typeof escalation === "object") {
    const esc = escalation as Record<string, unknown>
    if (typeof esc.consecutiveBlocks === "number" && esc.consecutiveBlocks > 0) {
      target.escalation.consecutiveBlocks = esc.consecutiveBlocks
    }
    if (typeof esc.totalBlocks === "number" && esc.totalBlocks > 0) {
      target.escalation.totalBlocks = esc.totalBlocks
    }
  }
}

function mergeEnvTrust(config: AutoModeGuardConfig) {
  const remotes = readEnv("OPENCODE_AUTO_MODE_TRUSTED_GIT_REMOTES")
  if (remotes) {
    config.environment.gitRemotes.push(...remotes.split(",").map((item) => item.trim()).filter(Boolean))
  }

  const domains = readEnv("OPENCODE_AUTO_MODE_TRUSTED_DOMAINS")
  if (domains) {
    config.environment.domains.push(...domains.split(",").map((item) => item.trim()).filter(Boolean))
  }
}

async function readJsonFile(filePath: string): Promise<Record<string, unknown> | undefined> {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8"))
  } catch {
    return undefined
  }
}

function readEnv(key: string): string | undefined {
  return (globalThis as any)?.process?.env?.[key]
}
