import { describe, expect, it, vi } from "vitest"
import AutoModeGuard from "../.opencode/plugins/auto-mode-guard"
import { createMockClient, userMessage } from "./helpers/mock-client"
import { harnessRoot } from "./helpers/paths"

describe("opencode runtime smoke", () => {
  it("exercises allow, hard-deny, and classifier-deny hook paths", async () => {
    const shell = vi.fn(async () => ({
      quiet: () => ({
        nothrow: async () => ({ exitCode: 0, stdout: "", stderr: "" }),
      }),
    }))

    const allowHooks = await AutoModeGuard({
      client: createMockClient({ messages: [userMessage("Fix src/safe.ts")], promptTexts: ["no"] }),
      $: shell,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    await expect(
      allowHooks["tool.execute.before"]?.(
        { tool: "edit", sessionID: "runtime-smoke-allow" },
        { args: { filePath: "src/safe.ts" } },
      ),
    ).resolves.toBeUndefined()

    const denyHooks = await AutoModeGuard({
      client: createMockClient({ messages: [userMessage("Debug")], promptTexts: ["no"] }),
      $: shell,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    await expect(
      denyHooks["tool.execute.before"]?.(
        { tool: "read", sessionID: "runtime-smoke-deny" },
        { args: { filePath: ".env" } },
      ),
    ).rejects.toThrow("Do not stop the task")

    const classifierHooks = await AutoModeGuard({
      client: createMockClient({
        messages: [userMessage("Run tests only.")],
        promptTexts: ["<score>no</score>"],
      }),
      $: shell,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    await expect(
      classifierHooks["tool.execute.before"]?.(
        { tool: "bash", sessionID: "runtime-smoke-classifier" },
        { args: { command: "git push upstream feature/test" } },
      ),
    ).rejects.toThrow("Do not stop the task")
  })
})
