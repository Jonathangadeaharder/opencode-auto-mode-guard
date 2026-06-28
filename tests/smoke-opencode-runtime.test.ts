import { describe, expect, it, vi } from "vitest"
import AutoModeGuard from "../.opencode/plugins/auto-mode-guard"
import { runRuntimeSmoke } from "../eval/runtime-smoke"
import { createMockClient, userMessage } from "./helpers/mock-client"
import { harnessRoot } from "./helpers/paths"

describe("opencode runtime smoke", () => {
  it("exercises allow, hard-deny, and classifier-deny hook paths", async () => {
    const shell = vi.fn(async () => ({
      quiet: () => ({
        nothrow: async () => ({ exitCode: 0, stdout: "", stderr: "" }),
      }),
    }))

    const hooks = await AutoModeGuard({
      client: createMockClient({
        messages: [userMessage("Run tests only.")],
        promptTexts: ["<score>no</score>"],
      }),
      $: shell,
      directory: harnessRoot,
      worktree: harnessRoot,
    })

    await expect(runRuntimeSmoke(hooks)).resolves.toBeUndefined()
  })
})
