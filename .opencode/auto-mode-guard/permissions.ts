import { promises as fs } from "node:fs"
import * as path from "node:path"
import { matchesPattern } from "./config"

export type OpenCodePermissionAction = "allow" | "ask" | "deny"

export interface OpenCodePermissionVerdict {
  action: OpenCodePermissionAction
  reason: string
  pattern?: string
}

type PermissionRuleMap = Record<string, string | Record<string, string>>

const CONFIG_CANDIDATES = ["opencode.json", ".opencode/opencode.json"]

export async function loadOpenCodePermissionRules(root: string): Promise<PermissionRuleMap | undefined> {
  for (const relative of CONFIG_CANDIDATES) {
    const filePath = path.join(root, relative)
    try {
      const parsed = JSON.parse(await fs.readFile(filePath, "utf8"))
      if (parsed?.permission && typeof parsed.permission === "object") {
        return parsed.permission as PermissionRuleMap
      }
    } catch {
      // try next candidate
    }
  }
  return undefined
}

export function evaluateOpenCodePermission(
  rules: PermissionRuleMap | undefined,
  tool: string,
  args: Record<string, unknown>,
): OpenCodePermissionVerdict | undefined {
  if (!rules) return undefined

  const wildcard = evaluatePermissionKey(rules, "*", tool, args)
  const specific = evaluatePermissionKey(rules, tool, tool, args)

  const candidates = [wildcard, specific].filter((item): item is OpenCodePermissionVerdict => Boolean(item))
  return candidates.at(-1)
}

function evaluatePermissionKey(
  rules: PermissionRuleMap,
  key: string,
  tool: string,
  args: Record<string, unknown>,
): OpenCodePermissionVerdict | undefined {
  const entry = rules[key]
  if (!entry) return undefined

  if (typeof entry === "string") {
    return toVerdict(entry, `OpenCode permission '${key}' is '${entry}'`)
  }

  const candidates = Object.entries(entry)
    .map(([pattern, action]) => {
      const subject = buildPermissionSubject(tool, args)
      if (!matchesPattern(pattern, subject) && !matchesPattern(pattern, tool)) {
        return undefined
      }
      return toVerdict(action, `OpenCode permission '${key}' pattern '${pattern}' matched`, pattern)
    })
    .filter((item): item is OpenCodePermissionVerdict => Boolean(item))

  return candidates.at(-1)
}

function buildPermissionSubject(tool: string, args: Record<string, unknown>): string {
  if (tool === "bash") {
    return String(args.command ?? args.cmd ?? tool)
  }

  const pathValue =
    args.filePath ??
    args.filepath ??
    args.path ??
    args.targetPath ??
    args.target ??
    args.url

  if (typeof pathValue === "string" && pathValue.trim()) {
    return `${tool} ${pathValue.trim()}`
  }

  return tool
}

function toVerdict(action: string, reason: string, pattern?: string): OpenCodePermissionVerdict | undefined {
  const normalized = action.toLowerCase()
  if (normalized !== "allow" && normalized !== "ask" && normalized !== "deny") {
    return undefined
  }

  return {
    action: normalized,
    reason,
    pattern,
  }
}
