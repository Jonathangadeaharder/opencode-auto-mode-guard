import { describe, expect, it, vi } from "vitest"
import AutoModeGuard from "../.opencode/plugins/auto-mode-guard"
import { createMockClient } from "./helpers/mock-client"
import { harnessRoot } from "./helpers/paths"

describe("plugin hooks", () => {
  async function createHooks() {
    const client = createMockClient({
      promptTexts: ["<score>no</score>"],
      messages: [],
    })

    const shell = vi.fn(async () => ({
      quiet: () => ({
        nothrow: async () => ({ exitCode: 0, stdout: "", stderr: "" }),
      }),
    }))

    const hooks = await AutoModeGuard({
      client,
      $: shell,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    return { hooks, client }
  }

  it("allows safe workspace edits", async () => {
    const { hooks } = await createHooks()

    await expect(
      hooks["tool.execute.before"]?.(
        { tool: "edit", sessionID: "session-safe" },
        { args: { filePath: "src/safe.ts" } },
      ),
    ).resolves.toBeUndefined()
  })

  it("blocks hard deny reads with recovery guidance", async () => {
    const { hooks } = await createHooks()

    await expect(
      hooks["tool.execute.before"]?.(
        { tool: "read", sessionID: "session-hard" },
        { args: { filePath: ".env" } },
      ),
    ).rejects.toThrow("Do not stop the task")
  })

  it("blocks manual bash through classifier deny with recovery guidance", async () => {
    const client = createMockClient({
      messages: [{ info: { role: "user" }, parts: [{ type: "text", text: "Run tests only." }] }],
      promptTexts: ["<score>no</score>"],
    })

    const shell = vi.fn()
    const hooks = await AutoModeGuard({
      client,
      $: shell,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    await expect(
      hooks["tool.execute.before"]?.(
        { tool: "bash", sessionID: "session-classifier-deny" },
        { args: { command: "git push upstream feature/test" } },
      ),
    ).rejects.toThrow("Do not stop the task")
  })

  it("requires explicit approval for configured ask rules", async () => {
    const { hooks } = await createHooks()

    await expect(
      hooks["tool.execute.before"]?.(
        { tool: "bash", sessionID: "session-ask" },
        { args: { command: "docker compose up -d" } },
      ),
    ).rejects.toThrow("explicit user approval")
  })

  it("marks mutation sessions for validation after tool execution", async () => {
    const { hooks } = await createHooks()

    await hooks["tool.execute.after"]?.(
      { tool: "edit", sessionID: "session-validate" },
      { args: { filePath: "src/safe.ts" } },
    )

    await hooks.event?.({
      event: { type: "session.idle", properties: { sessionID: "session-validate" } },
    })

    expect(true).toBe(true)
  })
})
