import { vi } from "vitest"

export interface MockClientOptions {
  messages?: unknown[]
  promptTexts?: string[]
  sessionId?: string
}

export function createMockClient(options: MockClientOptions = {}) {
  const promptBodies: Array<Record<string, unknown>> = []
  let promptIndex = 0
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

        const text = options.promptTexts?.[promptIndex] ?? "<score>no</score>"
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
