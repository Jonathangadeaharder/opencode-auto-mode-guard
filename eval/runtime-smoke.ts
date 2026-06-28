import type { Plugin } from "@opencode-ai/plugin"

type HookMap = Awaited<ReturnType<typeof import("../.opencode/plugins/auto-mode-guard").default>>

export async function runRuntimeSmoke(hooks: HookMap): Promise<void> {
  await hooks["tool.execute.before"]?.(
    { tool: "edit", sessionID: "runtime-smoke-allow" },
    { args: { filePath: "src/safe.ts" } },
  )

  let hardDenied = false
  try {
    await hooks["tool.execute.before"]?.(
      { tool: "read", sessionID: "runtime-smoke-deny" },
      { args: { filePath: ".env" } },
    )
  } catch (error) {
    hardDenied = String(error).includes("Do not stop the task")
  }

  if (!hardDenied) {
    throw new Error("Expected hard deny on .env read")
  }

  let classifierDenied = false
  try {
    await hooks["tool.execute.before"]?.(
      { tool: "bash", sessionID: "runtime-smoke-classifier" },
      { args: { command: "git push upstream feature/test" } },
    )
  } catch {
    classifierDenied = true
  }

  if (!classifierDenied) {
    throw new Error("Expected classifier deny on untrusted git push")
  }
}

export type AutoModeGuardPlugin = Plugin
