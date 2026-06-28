/** Bash patterns that always escalate past quick filter to full Granite review. */
export const CLASSIFIER_ESCALATION_BASH_PATTERNS: RegExp[] = [
  /\bgit\s+push\b[^;&|]*\b(main|master)\b/i,
  /\bgit\s+push\s+.*--force\b/i,
  /\bgit\s+push\s+origin\s+--delete\b/i,
  /\bgit\s+reset\s+--hard\b/i,
  /\bgit\s+rm\s+-/i,
  /\brm\s+-[^;&|]*r/i,
  /\bsudo\b/i,
  /\bcurl\b[^;&|]*\|\s*(sh|bash|zsh)\b/i,
  /\bwget\b[^;&|]*\|\s*(sh|bash|zsh)\b/i,
  /\bkubectl\b/i,
  /\bterraform\s+(apply|destroy)\b/i,
  /\bgh\s+run\s+cancel\b/i,
  /\bkill\s+-TERM\b/i,
]

export function matchesClassifierEscalationBash(command: string): boolean {
  return CLASSIFIER_ESCALATION_BASH_PATTERNS.some((pattern) => pattern.test(command))
}
