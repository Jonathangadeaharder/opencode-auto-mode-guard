import type { AutoModeGuardConfig } from "../../.opencode/auto-mode-guard/config"

export function createTestConfig(overrides: Partial<AutoModeGuardConfig> = {}): AutoModeGuardConfig {
  return {
    environment: {
      gitRemotes: overrides.environment?.gitRemotes ?? [],
      domains: overrides.environment?.domains ?? [],
    },
    ask: {
      bash: overrides.ask?.bash ?? [],
      tools: overrides.ask?.tools ?? ["webfetch", "websearch"],
    },
    escalation: {
      consecutiveBlocks: overrides.escalation?.consecutiveBlocks ?? 3,
      totalBlocks: overrides.escalation?.totalBlocks ?? 20,
    },
    classifierModel: overrides.classifierModel,
  }
}
