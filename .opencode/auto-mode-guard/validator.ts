import { promises as fs } from "node:fs"
import * as path from "node:path"

export interface PendingValidationState {
  sessionID: string
  reasons: string[]
  files: string[]
  lastMutationAt: string
}

export interface ValidationEngineOptions {
  client: any
  $: any
  directory: string
  worktree?: string
  log?: (
    level: "debug" | "info" | "warn" | "error",
    message: string,
    extra?: Record<string, unknown>,
  ) => Promise<void> | void
}

interface CommandResult {
  name: string
  command: string
  exitCode: number
  stdout: string
  stderr: string
}

interface ProjectInfo {
  root: string
  packageManager: "pnpm" | "bun" | "yarn" | "npm" | "unknown"
  packageJson?: {
    scripts?: Record<string, string>
    dependencies?: Record<string, string>
    devDependencies?: Record<string, string>
  }
  hasTSConfig: boolean
  hasBiomeConfig: boolean
}

const MAX_OUTPUT_CHARS = 12000

export function createValidator(options: ValidationEngineOptions) {
  return {
    async runForSession(sessionID: string, pending: PendingValidationState) {
      const project = await inspectProject(options.directory)
      const results: CommandResult[] = []

      await options.log?.("info", "Running post-mutation validation", {
        sessionID,
        root: project.root,
        packageManager: project.packageManager,
        files: pending.files,
      })

      if (project.hasBiomeConfig || hasDependency(project, "@biomejs/biome")) {
        results.push(await runBiome(options.$, project))
      } else {
        await options.log?.("debug", "Skipping Biome validation; no Biome config or dependency found", {
          sessionID,
        })
      }

      if (project.hasTSConfig || hasScript(project, "typecheck")) {
        results.push(await runTypecheck(options.$, project))
      } else {
        await options.log?.("debug", "Skipping TypeScript validation; no tsconfig or typecheck script found", {
          sessionID,
        })
      }

      const failures = results.filter((result) => result.exitCode !== 0)
      if (failures.length === 0) {
        await options.log?.("info", "Post-mutation validation passed", {
          sessionID,
          checks: results.map((result) => result.name),
        })
        return { ok: true, results }
      }

      await options.log?.("warn", "Post-mutation validation failed; injecting repair prompt", {
        sessionID,
        failures: failures.map((result) => result.name),
      })

      await injectRepairPrompt(options.client, sessionID, pending, failures)
      return { ok: false, results }
    },
  }
}

async function inspectProject(root: string): Promise<ProjectInfo> {
  const packageJsonPath = path.join(root, "package.json")
  const packageJson = await readPackageJson(packageJsonPath)

  return {
    root,
    packageManager: await detectPackageManager(root),
    packageJson,
    hasTSConfig: await exists(path.join(root, "tsconfig.json")),
    hasBiomeConfig:
      (await exists(path.join(root, "biome.json"))) ||
      (await exists(path.join(root, "biome.jsonc"))),
  }
}

async function detectPackageManager(root: string): Promise<ProjectInfo["packageManager"]> {
  if (await exists(path.join(root, "pnpm-lock.yaml"))) return "pnpm"
  if ((await exists(path.join(root, "bun.lockb"))) || (await exists(path.join(root, "bun.lock")))) return "bun"
  if (await exists(path.join(root, "yarn.lock"))) return "yarn"
  if (await exists(path.join(root, "package-lock.json"))) return "npm"
  if (await exists(path.join(root, "package.json"))) return "npm"
  return "unknown"
}

async function readPackageJson(filePath: string): Promise<ProjectInfo["packageJson"] | undefined> {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8"))
  } catch {
    return undefined
  }
}

async function runBiome($: any, project: ProjectInfo): Promise<CommandResult> {
  switch (project.packageManager) {
    case "pnpm":
      return capture("biome", "pnpm exec biome check --write .", await $`cd ${project.root} && pnpm exec biome check --write .`.quiet().nothrow())
    case "bun":
      return capture("biome", "bunx biome check --write .", await $`cd ${project.root} && bunx biome check --write .`.quiet().nothrow())
    case "yarn":
      return capture("biome", "yarn biome check --write .", await $`cd ${project.root} && yarn biome check --write .`.quiet().nothrow())
    case "npm":
    default:
      return capture("biome", "npx biome check --write .", await $`cd ${project.root} && npx biome check --write .`.quiet().nothrow())
  }
}

async function runTypecheck($: any, project: ProjectInfo): Promise<CommandResult> {
  if (hasScript(project, "typecheck")) {
    switch (project.packageManager) {
      case "pnpm":
        return capture("typecheck", "pnpm run typecheck", await $`cd ${project.root} && pnpm run typecheck`.quiet().nothrow())
      case "bun":
        return capture("typecheck", "bun run typecheck", await $`cd ${project.root} && bun run typecheck`.quiet().nothrow())
      case "yarn":
        return capture("typecheck", "yarn run typecheck", await $`cd ${project.root} && yarn run typecheck`.quiet().nothrow())
      case "npm":
      default:
        return capture("typecheck", "npm run typecheck", await $`cd ${project.root} && npm run typecheck`.quiet().nothrow())
    }
  }

  switch (project.packageManager) {
    case "pnpm":
      return capture("typecheck", "pnpm exec tsc --noEmit", await $`cd ${project.root} && pnpm exec tsc --noEmit`.quiet().nothrow())
    case "bun":
      return capture("typecheck", "bunx tsc --noEmit", await $`cd ${project.root} && bunx tsc --noEmit`.quiet().nothrow())
    case "yarn":
      return capture("typecheck", "yarn tsc --noEmit", await $`cd ${project.root} && yarn tsc --noEmit`.quiet().nothrow())
    case "npm":
    default:
      return capture("typecheck", "npx tsc --noEmit", await $`cd ${project.root} && npx tsc --noEmit`.quiet().nothrow())
  }
}

function capture(name: string, command: string, result: any): CommandResult {
  return {
    name,
    command,
    exitCode: Number(result?.exitCode ?? 1),
    stdout: truncate(toText(result?.stdout)),
    stderr: truncate(toText(result?.stderr)),
  }
}

async function injectRepairPrompt(
  client: any,
  sessionID: string,
  pending: PendingValidationState,
  failures: CommandResult[],
) {
  const text = buildRepairPrompt(pending, failures)

  await client.session.prompt({
    path: { id: sessionID },
    body: {
      parts: [{ type: "text", text }],
    },
  })
}

function buildRepairPrompt(pending: PendingValidationState, failures: CommandResult[]): string {
  const files = pending.files.length > 0 ? pending.files.map((file) => `- ${file}`).join("\n") : "- Unknown files"
  const reasons = pending.reasons.length > 0 ? pending.reasons.map((reason) => `- ${reason}`).join("\n") : "- Workspace mutation detected"

  const reports = failures
    .map((failure) => {
      const output = [failure.stderr, failure.stdout].filter(Boolean).join("\n") || "No output captured."
      return [
        `## ${failure.name}`,
        `Command: ${failure.command}`,
        `Exit code: ${failure.exitCode}`,
        "Output:",
        "```text",
        output,
        "```",
      ].join("\n")
    })
    .join("\n\n")

  return `Auto Mode Guard detected that your recent workspace changes broke project validation.

Recent mutation reasons:
${reasons}

Candidate files:
${files}

Repair the errors below. Keep the fix scoped to the files needed for validation. Do not modify secrets, .env files, CI/CD workflows, deployment files, Kubernetes manifests, Terraform, or OpenCode configuration unless the user explicitly requested that exact change.

${reports}`
}

function hasScript(project: ProjectInfo, scriptName: string): boolean {
  return typeof project.packageJson?.scripts?.[scriptName] === "string"
}

function hasDependency(project: ProjectInfo, packageName: string): boolean {
  return Boolean(
    project.packageJson?.dependencies?.[packageName] ||
      project.packageJson?.devDependencies?.[packageName],
  )
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath)
    return true
  } catch {
    return false
  }
}

function toText(value: unknown): string {
  if (value === undefined || value === null) return ""
  if (typeof value === "string") return value
  if (value instanceof Uint8Array) return new TextDecoder().decode(value)
  if (typeof (value as any)?.toString === "function") return String((value as any).toString())
  return String(value)
}

function truncate(value: string): string {
  if (value.length <= MAX_OUTPUT_CHARS) return value
  return `${value.slice(0, MAX_OUTPUT_CHARS)}\n... output truncated by Auto Mode Guard ...`
}
