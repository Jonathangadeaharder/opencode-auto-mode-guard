import path from "node:path"
import { fileURLToPath } from "node:url"

const testsDir = path.dirname(fileURLToPath(import.meta.url))

export const harnessRoot = path.resolve(testsDir, "../../fixtures/harness")
