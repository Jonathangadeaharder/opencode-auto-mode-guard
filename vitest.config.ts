import path from "node:path"
import { defineConfig } from "vitest/config"

export default defineConfig({
  resolve: {
    alias: {
      "@opencode-ai/plugin": path.resolve(__dirname, "types/@opencode-ai/plugin/index.d.ts"),
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    coverage: {
      provider: "v8",
      all: true,
      include: [".opencode/**/*.ts"],
      exclude: ["**/*.test.ts", "types/**"],
      reporter: ["text", "html", "clover"],
      thresholds: {
        branches: 60,
        lines: 75,
        functions: 85,
        statements: 75,
      },
    },
  },
})
