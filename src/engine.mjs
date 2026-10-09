// Policy engine: turns a hook payload into a decision.

import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { parse, unwrap, basename, isShell, positionals, flagSet } from './shell.mjs';
import { BASH_RULES, shellWriteTargets } from './rules/bash.mjs';
import { checkFileChange, checkFileRead, parseApplyPatch } from './rules/files.mjs';
import { scanSecrets } from './secrets.mjs';
import { isSecretFile, isEnvFile, isTemplateEnvFile } from './sensitive.mjs';

const SEVERITY = { allow: 0, ask: 1, deny: 2 };

export const ALL_RULES = [
  ...BASH_RULES.filter((r) => r.description),
  { id: 'sys.fork-bomb', description: 'Fork bombs' },
  { id: 'exec.inline-code', description: 'python -c / node -e / perl -e code that deletes / or $HOME, or shells out to a blocked command' },
  { id: 'exec.dynamic-command', description: 'Computed program names (`$(echo rm) -rf /`) with destructive-looking arguments' },
  { id: 'secrets.hardcoded', description: 'Writing provider API keys, tokens, private keys or DB URLs with passwords into non-env files (deny); heuristic matches (ask)' },
  { id: 'git.commit-secrets', description: 'Committing staged changes that contain secrets or credential files' },
  { id: 'exec.script-content', description: 'Writing a script file that contains a command which would be blocked if run directly' },
  { id: 'custom.deny', description: 'User-defined deny patterns from config' },
  { id: 'custom.ask', description: 'User-defined ask patterns from config' },
];

function ruleMatches(id, pattern) {
  if (pattern === id) return true;
  if (pattern.endsWith('*')) return id.startsWith(pattern.slice(0, -1));
  return false;
}

/** Apply disable/override config and keep the most severe finding first. */
export function resolveFindings(findings, config) {
  const kept = [];
  for (const f of findings) {
    if (config.disable.some((p) => ruleMatches(f.rule, p))) continue;
    const ov = Object.entries(config.overrides).find(([p]) => ruleMatches(f.rule, p));
    const level = ov ? ov[1] : f.level;
    if (level === 'allow') continue;
    if (level !== 'deny' && level !== 'ask') continue;
    kept.push({ ...f, level });
  }
  kept.sort((a, b) => SEVERITY[b.level] - SEVERITY[a.level]);
  // de-duplicate identical reasons
  const seen = new Set();
  return kept.filter((f) => (seen.has(f.reason) ? false : (seen.add(f.reason), true)));
}

const FORK_BOMB_RE = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&?\s*\}\s*;?\s*:|\b(\w+)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;\s*\1\b/;

function makeView(cmd, unwrapped, pipelineViews) {
  const offset = cmd.argv.length - unwrapped.argv.length;
  const words = cmd.words.slice(Math.max(0, offset));
  return {
    name: basename(unwrapped.argv[0] ?? ''),
    args: unwrapped.argv.slice(1),
    rawArgs: words.slice(1).map((w) => w.raw),
    words,
    wrappers: unwrapped.wrappers,
    env: cmd.env,
    redirects: cmd.redirects,
    heredocBodies: cmd.heredocs.map((h) => h.body ?? ''),
    pipeline: pipelineViews,
    pipeIndex: cmd.pipeIndex,
  };
}

/**
 * Evaluate a shell command string. Returns raw findings (not yet resolved
 * against overrides).
 */
export function evaluateShell(command, ctx, depth = 0) {
  const findings = [];
  if (depth > 6 || typeof command !== 'string' || !command.trim()) return findings;

  if (FORK_BOMB_RE.test(command)) {
    findings.push({ rule: 'sys.fork-bomb', level: 'deny', reason: 'This is a fork bomb; it would freeze the machine.' });
  }

  const { commands, nested } = parse(command, depth);

  // Build views grouped per pipeline so rules can look upstream.
  const byPipeline = new Map();
  const views = commands.map((cmd) => {
    const u = unwrap(cmd.argv);
    const list = byPipeline.get(cmd.pipeline) ?? [];
    byPipeline.set(cmd.pipeline, list);
    const view = makeView(cmd, u, list);
    list.push(view);
    return { cmd, u, view };
  });

  for (const { cmd, u, view } of views) {
    if (u.inner) {
      for (const f of evaluateShell(u.inner, ctx, depth + 1)) {
        findings.push({ ...f, reason: u.remote ? `On the remote host: ${f.reason}` : f.reason });
      }
    }

    // Shell reading a heredoc: evaluate the body as commands.
    if (isShell(view.name) && !u.inner) {
      for (const body of view.heredocBodies) findings.push(...evaluateShell(body, ctx, depth + 1));
    }

    // `echo 'rm -rf /' | sh` → evaluate what is echoed.
    if (isShell(view.name) && view.pipeIndex > 0 && positionals(view.args).length === 0) {
      const src = view.pipeline[view.pipeIndex - 1];
      if (src && (src.name === 'echo' || src.name === 'printf')) {
        findings.push(...evaluateShell(src.args.filter((a) => !a.startsWith('-')).join(' '), ctx, depth + 1));
      }
    }

    // Inline interpreter code: python -c, node -e, perl -e, ruby -e …
    const code = inlineCode(view);
    if (code) findings.push(...inspectInlineCode(code, view.name, ctx, depth));

    // `$(echo rm) -rf /` – the program name itself is computed at runtime.
    if (/^(\$|`)/.test(view.words[0]?.value ?? '') && view.args.length) {
      const probe = evaluateShell(`rm ${view.rawArgs.join(' ')}`, ctx, depth + 1).filter((f) => f.level === 'deny');
      if (probe.length) findings.push({ rule: 'exec.dynamic-command', level: 'ask', reason: `The program name \`${view.words[0].raw}\` is computed at runtime, and its arguments look destructive (${view.rawArgs.join(' ')}).` });
    }

    // Codex sometimes runs `apply_patch <<'EOF' … EOF` through the shell.
    if ((view.name === 'apply_patch' || view.name === 'applypatch') && view.heredocBodies.length) {
      findings.push(...evaluatePatch(view.heredocBodies.join('\n'), ctx));
    }

    if (!view.name) continue;

    for (const rule of BASH_RULES) {
      let res;
      try {
        res = rule.check(view, ctx);
      } catch (err) {
        res = null;
        ctx.errors?.push(`${rule.id}: ${err.message}`);
      }
      if (!res) continue;
      for (const f of Array.isArray(res) ? res : [res]) findings.push(f);
    }

    // Secrets written into files from the shell (heredoc / echo / printf).
    const targets = shellWriteTargets(view);
    if (targets.length) {
      const payload = [...view.heredocBodies, ...(view.name === 'echo' || view.name === 'printf' ? view.args : [])].join('\n');
      const high = scanSecrets(payload, { includeHeuristic: false });
      if (high.length) {
        findings.push({ rule: 'secrets.hardcoded', level: 'deny', reason: `Writing a ${high[0].name} [${high[0].preview}] into \`${targets[0].path}\`. Store secrets in an env file instead.` });
      }
    }

    if (view.name === 'git') findings.push(...checkCommitSecrets(view, views.map((v) => v.view), ctx));
  }

  for (const inner of nested) findings.push(...evaluateShell(inner, ctx, depth + 1));
  return findings;
}

const INLINE_FLAGS = {
  python: ['-c'], python3: ['-c'], python2: ['-c'], node: ['-e', '--eval', '-p', '--print'], deno: ['eval'], bun: ['-e', '--eval'],
  perl: ['-e', '-E'], ruby: ['-e'], php: ['-r'], osascript: ['-e'], pwsh: ['-c', '-Command'], powershell: ['-c', '-Command'],
};

function inlineCode(view) {
  const flags = INLINE_FLAGS[view.name];
  if (!flags) return null;
  const i = view.args.findIndex((a) => flags.includes(a));
  return i === -1 ? null : view.args[i + 1] ?? null;
}

const DANGEROUS_CODE = [
  { re: /\brmtree\s*\(\s*(?:r?["'](?:\/|~\/?)["']|os\.path\.expanduser\(\s*["']~["']\s*\)|Path\.home\(\)|os\.environ\[["']HOME["']\])/, reason: '`shutil.rmtree` on / or the home directory.' },
  { re: /\b(?:rmSync|rm|rmdirSync)\s*\(\s*(?:["'](?:\/|~\/?)["']|os\.homedir\(\)|process\.env\.HOME)\s*,\s*\{[^}]*recursive\s*:\s*true/, reason: '`fs.rmSync(..., { recursive: true })` on / or the home directory.' },
  { re: /\bFileUtils\.rm_r[f]?\s*\(\s*["'](?:\/|~)["']/, reason: '`FileUtils.rm_rf` on / or the home directory.' },
];

function inspectInlineCode(code, lang, ctx, depth) {
  const out = [];
  for (const d of DANGEROUS_CODE) if (d.re.test(code)) out.push({ rule: 'exec.inline-code', level: 'deny', reason: `Inline ${lang} code calls ${d.reason}` });
  // Shell commands embedded as string literals: os.system('…'), execSync('…'), `…`
  const literal = /(["'`])((?:\\.|(?!\1)[^\\])*)\1/g;
  let m;
  while ((m = literal.exec(code)) !== null) {
    const text = m[2];
    if (text.length < 4 || !/\s/.test(text)) continue;
    for (const f of evaluateShell(text, ctx, depth + 1)) {
      if (f.level === 'deny') out.push({ ...f, reason: `Inline ${lang} code runs a shell command: ${f.reason}` });
    }
  }
  return out;
}

function evaluatePatch(patchText, ctx) {
  const out = [];
  for (const change of parseApplyPatch(patchText)) {
    out.push(...checkFileChange(change, ctx, (text) => evaluateShell(text, ctx, 1)));
  }
  return out;
}

// ---------------------------------------------------------------------------
// git commit: scan what is about to be committed
// ---------------------------------------------------------------------------

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', timeout: 4000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
}

function gitSubcommand(view) {
  const a = view.args;
  let i = 0;
  while (i < a.length && a[i].startsWith('-')) i += a[i] === '-C' || a[i] === '-c' ? 2 : 1;
  return { sub: a[i], rest: a.slice(i + 1) };
}

function checkCommitSecrets(view, allViews, ctx) {
  const { sub, rest } = gitSubcommand(view);
  if (sub !== 'commit' || ctx.skipGit) return [];
  const flags = flagSet(rest);
  // Did an earlier command in this same line stage everything? (git add . / -A)
  const stagesAll = allViews.some((v) => v !== view && v.name === 'git' && ['add', 'stage'].includes(gitSubcommand(v).sub) && gitSubcommand(v).rest.some((a) => a === '.' || a === '-A' || a === '--all' || a === ':/'));
  const includeWorktree = flags.has('a', '--all') || stagesAll;

  let diff = '';
  let untracked = [];
  try {
    diff = git(['diff', '--cached', '--no-color', '--no-ext-diff', '-U0'], ctx.cwd);
    if (includeWorktree) diff += '\n' + git(['diff', '--no-color', '--no-ext-diff', '-U0'], ctx.cwd);
    if (stagesAll) untracked = git(['ls-files', '--others', '--exclude-standard'], ctx.cwd).split('\n').filter(Boolean).slice(0, 300);
  } catch {
    return []; // not a git repo, git missing, timeout … nothing to scan
  }

  const files = new Map(); // path → added text
  let current = null;
  for (const line of diff.split('\n')) {
    if (line.startsWith('+++ ')) {
      const p = line.slice(4).replace(/^b\//, '');
      current = p === '/dev/null' ? null : p;
      if (current && !files.has(current)) files.set(current, []);
      continue;
    }
    if (current && line.startsWith('+') && !line.startsWith('+++')) files.get(current).push(line.slice(1));
  }
  for (const p of untracked) {
    try {
      const full = join(ctx.cwd, p);
      if (statSync(full).size > 512 * 1024) continue;
      files.set(p, [readFileSync(full, 'utf8')]);
    } catch {
      /* unreadable → skip */
    }
  }

  const out = [];
  for (const [path, lines] of files) {
    if (isSecretFile(path) && !isTemplateEnvFile(path)) {
      out.push({ rule: 'git.commit-secrets', level: 'deny', reason: `The commit would include \`${path}\`, which looks like a credentials file. Unstage it (\`git restore --staged ${path}\`) and add it to .gitignore.` });
      continue;
    }
    if (isEnvFile(path) && !isTemplateEnvFile(path)) continue;
    const found = scanSecrets(lines.join('\n'));
    const high = found.find((f) => f.confidence === 'high');
    if (high) out.push({ rule: 'git.commit-secrets', level: 'deny', reason: `The commit would add a ${high.name} [${high.preview}] in \`${path}\`. Remove it from the change and load it from the environment instead.` });
    else if (found.length) out.push({ rule: 'git.commit-secrets', level: 'ask', reason: `The commit may add a hard-coded secret in \`${path}\`: ${found[0].name} [${found[0].preview}].` });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function contentOf(toolName, input) {
  switch (toolName) {
    case 'Write':
      return [{ path: input.file_path ?? input.path, op: 'write', content: input.content ?? '' }];
    case 'Edit':
      return [{ path: input.file_path ?? input.path, op: 'edit', content: input.new_string ?? '' }];
    case 'MultiEdit':
      return [{ path: input.file_path ?? input.path, op: 'edit', content: (input.edits ?? []).map((e) => e?.new_string ?? '').join('\n') }];
    case 'NotebookEdit':
      return [{ path: input.notebook_path ?? input.file_path, op: 'edit', content: input.new_source ?? '' }];
    default:
      return [];
  }
}

function matchCustom(list, command) {
  for (const r of list) {
    try {
      if (new RegExp(r.pattern).test(command)) return r;
    } catch {
      /* invalid regex in config → ignore */
    }
  }
  return null;
}

/**
 * Evaluate a hook payload.
 * @returns {{ decision: 'allow'|'ask'|'deny', findings: Array, summary: string }}
 */
export function evaluate(payload, ctx) {
  const toolName = payload.tool_name ?? '';
  const input = payload.tool_input ?? {};
  let raw = [];

  if (toolName === 'Bash' || toolName === 'shell' || toolName === 'local_shell' || toolName === 'exec_command') {
    const command = Array.isArray(input.command) ? input.command.join(' ') : String(input.command ?? input.cmd ?? '');
    if (ctx.config.allow.some((p) => safeTest(p, command))) return { decision: 'allow', findings: [], summary: 'allowed by config' };
    const d = matchCustom(ctx.config.deny, command);
    if (d) raw.push({ rule: 'custom.deny', level: 'deny', reason: d.reason ?? `Matches deny pattern \`${d.pattern}\` from agent-guard config.` });
    const a = matchCustom(ctx.config.ask, command);
    if (a) raw.push({ rule: 'custom.ask', level: 'ask', reason: a.reason ?? `Matches ask pattern \`${a.pattern}\` from agent-guard config.` });
    raw.push(...evaluateShell(command, ctx));
  } else if (toolName === 'apply_patch' || toolName === 'ApplyPatch') {
    raw.push(...evaluatePatch(String(input.command ?? input.patch ?? input.input ?? ''), ctx));
  } else if (['Write', 'Edit', 'MultiEdit', 'NotebookEdit'].includes(toolName)) {
    for (const change of contentOf(toolName, input)) {
      if (!change.path) continue;
      raw.push(...checkFileChange(change, ctx, (text) => evaluateShell(text, ctx, 1)));
    }
  } else if (toolName === 'Read') {
    if (input.file_path) raw.push(...checkFileRead(input.file_path, ctx));
  }

  const findings = resolveFindings(raw, ctx.config);
  const decision = findings[0]?.level ?? 'allow';
  return { decision, findings, summary: findings.map((f) => `[${f.rule}] ${f.reason}`).join('\n') };
}

function safeTest(pattern, text) {
  try {
    return new RegExp(pattern).test(text);
  } catch {
    return false;
  }
}
