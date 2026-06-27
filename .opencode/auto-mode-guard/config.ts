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
  classifierModel?: string
}

export interface ResolvedClassifierModel {
  providerID: string
  modelID: string
  source: "env" | "guard-config" | "small_model" | "main_model"
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

const OPENCODE_CONFIG_CANDIDATES = ["opencode.json", ".opencode/opencode.json"]

export async function loadMergedOpenCodeConfig(root: string): Promise<Record<string, unknown>> {
  let merged: Record<string, unknown> = {}

  const globalPath = path.join(readHomeDir(), ".config/opencode/opencode.json")
  const globalConfig = await readJsonFile(globalPath)
  if (globalConfig) {
    merged = { ...merged, ...globalConfig }
  }

  for (const relative of OPENCODE_CONFIG_CANDIDATES) {
    const fromFile = await readJsonFile(path.join(root, relative))
    if (fromFile) {
      merged = { ...merged, ...fromFile }
    }
  }

  return merged
}

export function parseModelRef(raw: string | undefined): { providerID: string; modelID: string } | undefined {
  if (!raw?.trim()) return undefined

  const [providerID, ...modelParts] = raw.trim().split("/")
  const modelID = modelParts.join("/")

  if (!providerID || !modelID) {
    return undefined
  }

  return { providerID, modelID }
}

export async function resolveClassifierModel(
  root: string,
  guardConfig: AutoModeGuardConfig,
): Promise<ResolvedClassifierModel | undefined> {
  const envModel = parseModelRef(readEnv("OPENCODE_AUTO_MODE_CLASSIFIER_MODEL"))
  if (envModel) {
    return { ...envModel, source: "env" }
  }

  const guardModel = parseModelRef(guardConfig.classifierModel)
  if (guardModel) {
    return { ...guardModel, source: "guard-config" }
  }

  const opencode = await loadMergedOpenCodeConfig(root)

  const smallModel = parseModelRef(readString(opencode.small_model))
  if (smallModel) {
    return { ...smallModel, source: "small_model" }
  }

  const mainModel = parseModelRef(readString(opencode.model))
  if (mainModel) {
    return { ...mainModel, source: "main_model" }
  }

  return undefined
}

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

  if (typeof source.classifierModel === "string" && source.classifierModel.trim()) {
    target.classifierModel = source.classifierModel.trim()
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

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined
}

function readHomeDir(): string {
  return (globalThis as any)?.process?.env?.HOME ?? (globalThis as any)?.process?.env?.USERPROFILE ?? ""
}

function readEnv(key: string): string | undefined {
  return (globalThis as any)?.process?.env?.[key]
}
