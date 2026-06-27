# Auto Mode Guard tests

## Commands

```bash
pnpm test              # unit + integration matrix
pnpm run test:watch    # watch mode
pnpm run test:coverage # coverage report in coverage/
pnpm run typecheck
```

## Layout

| Path | Purpose |
|------|---------|
| `tests/policy.test.ts` | Static policy rules |
| `tests/permissions.test.ts` | `opencode.json` permission matching |
| `tests/config.test.ts` | Config merge + pattern helpers |
| `tests/block-handler.test.ts` | Recover / escalate counters |
| `tests/classifier.test.ts` | Mock SDK contract tests |
| `tests/plugin.test.ts` | Hook wiring smoke tests |
| `tests/integration/matrix.test.ts` | Scenarios A–I against fixture repo |
| `fixtures/harness/` | Minimal git-like project for integration |
| `tests/helpers/` | Shared mocks and config builders |

## Integration matrix

| ID | Action | Expected |
|----|--------|----------|
| A | edit `src/safe.ts` | allow |
| B | edit `.github/workflows/ci.yml` | manual |
| C | `git push origin` | allow |
| D | `git push upstream` | manual |
| E | `pnpm test` | allow |
| F | `sudo rm -rf /` | deny |
| G | read `.env` | deny |
| H | `webfetch` unknown URL | ask |
| I | `docker compose up` | ask |

## Coverage targets

Current enforced floors (see `vitest.config.ts`):

- branches: 60% (classifier/plugin error paths still thin)
- lines/statements: 75%
- functions: 85%

Raise toward 90% branch coverage by adding classifier fallback-path tests and plugin escalation tests.

See `fixtures/harness/README.md`.
