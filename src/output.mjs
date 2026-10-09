// Turn an engine result into the hook response for each agent.
//
// Claude Code: permissionDecision supports allow | deny | ask | defer.
// Codex:       permissionDecision supports deny (and allow + updatedInput);
//              "ask" is NOT supported and would make the hook fail open.

export function detectPlatform(payload, env = process.env) {
  if (env.AGENT_GUARD_PLATFORM === 'codex' || env.AGENT_GUARD_PLATFORM === 'claude') return env.AGENT_GUARD_PLATFORM;
  if (payload && Object.prototype.hasOwnProperty.call(payload, 'turn_id')) return 'codex';
  if (payload?.tool_name === 'apply_patch') return 'codex';
  return 'claude';
}

const FOOTER_DENY =
  'Do not try to achieve the same effect another way (other commands, scripts, encoding, or editing the guard config). ' +
  'Explain to the user what you wanted to do and why; they can run it themselves or adjust the agent-guard policy.';

const FOOTER_ASK_CODEX =
  'This action needs explicit human approval, and this agent cannot show an approval prompt. ' +
  'Stop and ask the user to confirm. If they agree, they can run the command themselves or allow it in their agent-guard config. ' +
  'Do not work around this check.';

export function formatReason(result, { platform, level }) {
  const lines = result.findings.slice(0, 3).map((f) => `• ${f.reason} [${f.rule}]`);
  if (result.findings.length > 3) lines.push(`• …and ${result.findings.length - 3} more`);
  const head = level === 'deny' ? 'agent-guard blocked this action:' : 'agent-guard: this action needs your approval:';
  const footer = level === 'deny' ? FOOTER_DENY : platform === 'codex' ? FOOTER_ASK_CODEX : '';
  return [head, ...lines, footer].filter(Boolean).join('\n');
}

/**
 * @returns {{ stdout: string, exitCode: number }}
 */
export function toHookResponse(result, { platform, config }) {
  if (result.decision === 'allow' || config.mode === 'audit') return { stdout: '', exitCode: 0 };

  let level = result.decision;
  if (platform === 'codex' && level === 'ask') {
    if (config.codexAskBehavior === 'allow') return { stdout: '', exitCode: 0 };
    level = 'deny';
  }

  const reason = formatReason(result, { platform, level: result.decision === 'ask' && platform === 'codex' ? 'ask' : level });
  const body = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: level,
      permissionDecisionReason: reason,
    },
  };
  return { stdout: JSON.stringify(body), exitCode: 0 };
}
