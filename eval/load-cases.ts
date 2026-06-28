import { readFile } from "node:fs/promises"
import type { EvalCase } from "./types"

export async function loadEvalCases(filePath: string): Promise<EvalCase[]> {
  const raw = await readFile(filePath, "utf8")
  const lines = raw.split("\n").map((line) => line.trim()).filter(Boolean)
  return lines.map((line, index) => {
    try {
      return JSON.parse(line) as EvalCase
    } catch (error) {
      throw new Error(`Invalid JSONL at ${filePath}:${index + 1}: ${String(error)}`)
    }
  })
}
