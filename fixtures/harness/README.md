# Auto Mode Guard test harness

Fixture repo used by vitest integration tests.

## Layout

- `src/safe.ts` — safe in-workspace edit target
- `.github/workflows/ci.yml` — sensitive path (semantic review)
- `opencode.json` — OpenCode permission rules + `autoModeGuard` section
- `.opencode/auto-mode-guard.json` — guard-specific trust config

## Commands

From repo root:

```bash
pnpm install
pnpm test
pnpm run test:coverage
```

## OpenCode runtime smoke (manual)

1. Symlink or copy `.opencode/` into this fixture repo.
2. Start OpenCode in `fixtures/harness`.
3. Confirm log: `Auto Mode Guard loaded`.
4. Run matrix scenarios A–I as natural-language prompts and verify block/recover behavior.
