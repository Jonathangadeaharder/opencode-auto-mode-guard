#!/usr/bin/env node
/**
 * OpenCode runtime smoke — exercises AutoModeGuard plugin hooks without a live server.
 * Set OPENCODE_LIVE=1 to require a running `opencode serve` (not implemented here).
 */
import AutoModeGuard from "../.opencode/plugins/auto-mode-guard"
import { createMockClient, userMessage } from "../tests/helpers/mock-client"
import path from "node:path"
import { fileURLToPath } from "node:url"

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const harnessRoot = path.join(repoRoot, "fixtures/harness")

async function run() {
  if (process.env.OPENCODE_LIVE === "1") {
    console.error("OPENCODE_LIVE=1 not wired yet — use mocked hook smoke (default).")
    process.exit(2)
  }

  const shell = async () => ({
    quiet: () => ({
      nothrow: async () => ({ exitCode: 0, stdout: "", stderr: "" }),
    }),
  })

  const allowClient = createMockClient({
    messages: [userMessage("Fix src/safe.ts")],
    promptTexts: ["no"],
  })

  const allowHooks = await AutoModeGuard({
    client: allowClient,
    $: shell,
    directory: harnessRoot,
    worktree: harnessRoot,
  })

  await allowHooks["tool.execute.before"]?.(
    { tool: "edit", sessionID: "smoke-allow" },
    { args: { filePath: "src/safe.ts" } },
  )
  console.log("✓ allow path: edit src/safe.ts")

  const denyClient = createMockClient({
    messages: [userMessage("Debug the app.")],
    promptTexts: ["no"],
  })

  const denyHooks = await AutoModeGuard({
    client: denyClient,
    $: shell,
    directory: harnessRoot,
    worktree: harnessRoot,
  })

  let denied = false
  try {
    await denyHooks["tool.execute.before"]?.(
      { tool: "read", sessionID: "smoke-deny" },
      { args: { filePath: ".env" } },
    )
  } catch (error) {
    denied = true
    const message = error instanceof Error ? error.message : String(error)
    if (!message.includes("Do not stop the task")) {
      throw error
    }
  }

  if (!denied) {
    throw new Error("Expected hard deny on .env read")
  }
  console.log("✓ deny path: read .env blocked with recovery guidance")

  const classifierClient = createMockClient({
    messages: [userMessage("Run tests only.")],
    promptTexts: ["<score>no</score>"],
  })

  const classifierHooks = await AutoModeGuard({
    client: classifierClient,
    $: shell,
    directory: harnessRoot,
    worktree: harnessRoot,
  })

  let classifierDenied = false
  try {
    await classifierHooks["tool.execute.before"]?.(
      { tool: "bash", sessionID: "smoke-classifier" },
      { args: { command: "git push upstream feature/test" } },
    )
  } catch (error) {
    classifierDenied = true
  }

  if (!classifierDenied) {
    throw new Error("Expected classifier deny on untrusted git push")
  }
  console.log("✓ semantic path: manual bash blocked after classifier deny")

  console.log("\nRuntime smoke passed (mocked hooks).")
}

run().catch((error) => {
  console.error(error)
  process.exit(1)
})
