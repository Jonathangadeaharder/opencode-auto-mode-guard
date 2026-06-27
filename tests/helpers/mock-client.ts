import { vi } from "vitest"

export interface MockClientOptions {
  messages?: unknown[]
  promptTexts?: string[]
  structuredOutputs?: unknown[]
  sessionId?: string
}

export function createMockClient(options: MockClientOptions = {}) {
  const promptBodies: Array<Record<string, unknown>> = []
  let promptIndex = 0
  const structuredQueue = [...(options.structuredOutputs ?? [])]
  const sessionId = options.sessionId ?? "classifier-session-test"

  const client = {
    promptBodies,
    session: {
      messages: vi.fn(async () => options.messages ?? []),
      create: vi.fn(async () => ({ id: sessionId, data: { id: sessionId } })),
      prompt: vi.fn(async (request: { body?: Record<string, unknown> }) => {
        if (request.body) {
          promptBodies.push(request.body)
        }

        const hasStructuredFormat = Boolean(request.body?.format || request.body?.outputFormat)
        if (hasStructuredFormat) {
          const structured = structuredQueue.shift()
          promptIndex += 1
          if (structured) {
            return {
              data: {
                info: { structured_output: structured },
                parts: [],
              },
            }
          }
        }

        const text = options.promptTexts?.[promptIndex] ?? "no"
        promptIndex += 1

        return {
          data: {
            parts: [{ type: "text", text }],
          },
        }
      }),
      delete: vi.fn(async () => {}),
    },
    app: {
      log: vi.fn(async () => {}),
    },
  }

  return client
}

export function userMessage(text: string) {
  return {
    info: { role: "user" },
    parts: [{ type: "text", text }],
  }
}

export function assistantMessage(text: string, toolCalls: Array<{ tool: string; args: Record<string, unknown> }> = []) {
  return {
    info: { role: "assistant" },
    parts: [
      ...(text ? [{ type: "text", text }] : []),
      ...toolCalls.map((call) => ({
        type: "tool",
        tool: call.tool,
        name: call.tool,
        args: call.args,
      })),
    ],
  }
}
