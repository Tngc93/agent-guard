// Append-only JSONL audit log of non-allow decisions. Secret values are redacted
// before anything is written.

import { appendFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { redactSecretsInText } from './secrets.mjs';

export function auditLogPath(env = process.env) {
  if (env.AGENT_GUARD_AUDIT_LOG) return env.AGENT_GUARD_AUDIT_LOG;
  const base = env.CLAUDE_PLUGIN_DATA || env.PLUGIN_DATA || join(env.XDG_STATE_HOME || join(env.HOME || homedir(), '.local', 'state'), 'agent-guard');
  return join(base, 'audit.jsonl');
}

function summarizeInput(toolName, input) {
  if (!input || typeof input !== 'object') return '';
  if (typeof input.command === 'string') return input.command.slice(0, 2000);
  if (Array.isArray(input.command)) return input.command.join(' ').slice(0, 2000);
  return String(input.file_path ?? input.notebook_path ?? input.path ?? '').slice(0, 500);
}

export function writeAudit({ payload, result, platform, mode }, env = process.env) {
  try {
    const path = auditLogPath(env);
    mkdirSync(dirname(path), { recursive: true });
    const entry = {
      ts: new Date().toISOString(),
      platform,
      mode,
      decision: result.decision,
      tool: payload.tool_name,
      cwd: payload.cwd,
      session: payload.session_id,
      input: redactSecretsInText(summarizeInput(payload.tool_name, payload.tool_input)),
      findings: result.findings.map((f) => ({ rule: f.rule, level: f.level, reason: redactSecretsInText(f.reason) })),
    };
    appendFileSync(path, JSON.stringify(entry) + '\n', { mode: 0o600 });
  } catch {
    /* auditing must never break the hook */
  }
}
