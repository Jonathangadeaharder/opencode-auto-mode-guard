#!/usr/bin/env tsx
import AutoModeGuard from "../.opencode/plugins/auto-mode-guard"
import { runRuntimeSmoke } from "../eval/runtime-smoke"
import { createMockClient, userMessage } from "../tests/helpers/mock-client"
import { harnessRoot } from "../tests/helpers/paths"

async function run() {
  const shell = async () => ({
    quiet: () => ({
      nothrow: async () => ({ exitCode: 0, stdout: "", stderr: "" }),
    }),
  })

  const hooks = await AutoModeGuard({
    client: createMockClient({
      messages: [userMessage("Run tests only.")],
      promptTexts: ["<score>no</score>"],
    }),
    $: shell,
    directory: harnessRoot,
    worktree: harnessRoot,
  })

  await runRuntimeSmoke(hooks)
  console.log("\nRuntime smoke passed (mocked hooks).")
}

run().catch((error) => {
  console.error(error)
  process.exit(1)
})
