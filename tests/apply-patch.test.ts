import { describe, expect, it } from "vitest"
import { extractPatchPaths } from "../.opencode/auto-mode-guard/policy"

describe("apply_patch path extraction", () => {
  it("extracts paths from OpenCode patch headers", () => {
    const patchText = `*** Begin Patch
*** Update File: src/safe.ts
@@
-export const value = 1
+export const value = 2
*** End Patch`

    expect(extractPatchPaths(patchText)).toEqual(["src/safe.ts"])
  })

  it("extracts multiple paths from unified diff headers", () => {
    const patchText = `--- a/src/old.ts
+++ b/src/new.ts
@@
-const x = 1
+const x = 2`

    expect(extractPatchPaths(patchText)).toEqual(["src/old.ts", "src/new.ts"])
  })

  it("extracts sensitive workflow paths embedded in patchText", () => {
    const patchText = `*** Begin Patch
*** Update File: .github/workflows/ci.yml
@@
+name: ci
*** End Patch`

    expect(extractPatchPaths(patchText)).toContain(".github/workflows/ci.yml")
  })

  it("ignores /dev/null diff placeholders", () => {
    const patchText = `--- a/src/new.ts
+++ b/dev/null`

    expect(extractPatchPaths(patchText)).toEqual(["src/new.ts"])
  })
})
