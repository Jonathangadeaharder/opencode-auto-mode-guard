export interface PluginContext {
  client: unknown
  $: unknown
  directory: string
  worktree?: string
}

export interface PluginHooks {
  "tool.execute.before"?: (input: unknown, output: unknown) => Promise<void> | void
  "tool.execute.after"?: (input: unknown, output: unknown) => Promise<void> | void
  event?: (payload: { event: unknown }) => Promise<void> | void
}

export type Plugin = (context: PluginContext) => Promise<PluginHooks>
