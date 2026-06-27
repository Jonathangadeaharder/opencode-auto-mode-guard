import type { AutoModeGuardConfig } from "../../.opencode/auto-mode-guard/config"

export function createTestConfig(overrides: Partial<AutoModeGuardConfig> = {}): AutoModeGuardConfig {
  return {
    environment: {
      gitRemotes: [],
      domains: [],
      ...overrides.environment,
    },
    ask: {
      bash: [],
      tools: ["webfetch", "websearch"],
      ...overrides.ask,
    },
    escalation: {
      consecutiveBlocks: 3,
      totalBlocks: 20,
      ...overrides.escalation,
    },
  }
}
