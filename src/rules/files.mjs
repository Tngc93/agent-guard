// Rules for file tools: Write / Edit / MultiEdit / NotebookEdit / Read (Claude
// Code) and apply_patch (Codex).

import { scanSecrets } from '../secrets.mjs';
import { expandPath, isWithin, matchesAnyGlob } from '../paths.mjs';
import { isEnvFile, isTemplateEnvFile, isGuardConfigFile, isPersistenceFile, isGitInternal, isScriptFile, isSecretFile } from '../sensitive.mjs';

const finding = (rule, level, reason) => ({ rule, level, reason });
const SYSTEM_WRITE_RE = /^\/(bin|sbin|usr|System|boot|lib|lib64)(\/|$)/;

function relToProject(abs, ctx) {
  return isWithin(abs, ctx.projectDir) && abs !== ctx.projectDir ? abs.slice(ctx.projectDir.length + 1) : abs;
}

/**
 * @param {{ path: string, content?: string, op: 'write'|'edit'|'delete'|'move' }} change
 * @param {object} ctx
 * @param {(cmd: string) => Array} evaluateShellText  used to inspect script contents
 */
export function checkFileChange(change, ctx, evaluateShellText) {
  const out = [];
  const e = expandPath(change.path, ctx);
  const abs = e.abs ?? change.path;
  const display = relToProject(abs, ctx);

  if (SYSTEM_WRITE_RE.test(abs)) {
    out.push(finding('fs.protected-write', 'deny', `Writing to system path \`${abs}\`.`));
  } else if (isGitInternal(abs)) {
    out.push(finding('fs.protected-write', 'deny', `Directly editing git internals (\`${display}\`) can corrupt the repository. Use git commands instead.`));
  } else if (isGuardConfigFile(abs)) {
    out.push(finding('fs.protected-write', 'ask', `\`${display}\` configures the agent's own guard rails/hooks. Changes here need a human.`));
  } else if (isPersistenceFile(abs)) {
    out.push(finding('fs.protected-write', 'ask', `\`${display}\` is a shell startup, SSH access or system file.`));
  } else if (ctx.config.protectedPaths.length && matchesAnyGlob(display, ctx.config.protectedPaths)) {
    out.push(finding('fs.protected-write', 'ask', `\`${display}\` is listed in protectedPaths.`));
  }

  if (change.op === 'delete' || change.op === 'move') return out;

  const content = change.content ?? '';
  if (content) {
    const envTarget = isEnvFile(abs) && !isTemplateEnvFile(abs);
    if (!envTarget) {
      const secrets = scanSecrets(content);
      const high = secrets.filter((s) => s.confidence === 'high');
      const medium = secrets.filter((s) => s.confidence !== 'high');
      const where = isTemplateEnvFile(abs) ? ' (a committed template file)' : '';
      if (high.length) {
        out.push(finding('secrets.hardcoded', 'deny', `Hard-coded ${describe(high)} in \`${display}\`${where}. Put it in an env file (e.g. .env, git-ignored) and read it from the environment instead.`));
      } else if (medium.length) {
        out.push(finding('secrets.hardcoded', 'ask', `Possible hard-coded secret in \`${display}\`${where}: ${describe(medium)}. If it is real, move it to an env file.`));
      }
    }
    if (isScriptFile(abs) && typeof evaluateShellText === 'function') {
      const inner = evaluateShellText(content).filter((f) => f.level === 'deny');
      if (inner.length) {
        out.push(finding('exec.script-content', 'ask', `Script \`${display}\` contains a command that would be blocked if run directly: ${inner[0].reason}`));
      }
    }
  }
  return out;
}

function describe(findings) {
  const first = findings[0];
  const extra = findings.length > 1 ? ` (+${findings.length - 1} more)` : '';
  return `${first.name} on line ${first.line} [${first.preview}]${extra}`;
}

export function checkFileRead(path, ctx) {
  const e = expandPath(path, ctx);
  const abs = e.abs ?? path;
  if (isSecretFile(abs)) {
    return [finding('secrets.read', 'ask', `Reading \`${relToProject(abs, ctx)}\` puts credentials into the conversation/transcript.`)];
  }
  return [];
}

/**
 * Parse a Codex apply_patch payload.
 * @returns {Array<{ path, op, content }>}
 */
export function parseApplyPatch(text) {
  const changes = [];
  let current = null;
  for (const line of String(text ?? '').split('\n')) {
    let m;
    if ((m = line.match(/^\*\*\* (Add|Update|Delete) File: (.+)$/))) {
      current = { path: m[2].trim(), op: m[1] === 'Delete' ? 'delete' : m[1] === 'Add' ? 'write' : 'edit', lines: [] };
      changes.push(current);
      continue;
    }
    if ((m = line.match(/^\*\*\* Move to: (.+)$/)) && current) {
      changes.push({ path: current.path, op: 'move', lines: [] });
      current.path = m[1].trim();
      continue;
    }
    if (line.startsWith('*** ')) continue;
    if (current && line.startsWith('+')) current.lines.push(line.slice(1));
  }
  return changes.map((c) => ({ path: c.path, op: c.op, content: c.lines.join('\n') }));
}
