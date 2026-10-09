#!/usr/bin/env node
// agent-guard CLI
//
//   agent-guard hook                 Read a PreToolUse payload on stdin (used by Claude Code / Codex)
//   agent-guard check "<command>"    Explain what the guard would do with a shell command
//   agent-guard scan [files…]        Scan files (or --staged changes) for secrets
//   agent-guard rules                List rules and their ids
//   agent-guard install <claude|codex> [--project] [--dry-run]
//   agent-guard doctor               Show config, audit log location and environment

import { readFileSync, writeFileSync, existsSync, mkdirSync, copyFileSync, statSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { homedir } from 'node:os';

import { evaluate, ALL_RULES } from '../src/engine.mjs';
import { loadConfig, userConfigPath, projectConfigPath } from '../src/config.mjs';
import { makeContext } from '../src/paths.mjs';
import { detectPlatform, toHookResponse } from '../src/output.mjs';
import { writeAudit, auditLogPath } from '../src/audit.mjs';
import { scanSecrets } from '../src/secrets.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const PKG = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

function readStdin() {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

function buildContext({ cwd, env = process.env }) {
  const projectDir = env.CLAUDE_PROJECT_DIR || cwd;
  const { config, warnings, sources } = loadConfig({ projectDir, env });
  const ctx = { ...makeContext({ cwd, projectDir, env }), config, errors: [] };
  return { ctx, warnings, sources };
}

// ---------------------------------------------------------------------------

function cmdHook() {
  let config = null;
  try {
    const raw = readStdin();
    const payload = raw.trim() ? JSON.parse(raw) : {};
    const cwd = payload.cwd || process.cwd();
    const built = buildContext({ cwd });
    config = built.ctx.config;
    const platform = detectPlatform(payload);
    const result = evaluate(payload, built.ctx);
    if (result.decision !== 'allow' && config.auditLog) writeAudit({ payload, result, platform, mode: config.mode });
    const { stdout, exitCode } = toHookResponse(result, { platform, config });
    if (stdout) process.stdout.write(stdout + '\n');
    for (const w of built.warnings) process.stderr.write(`agent-guard: ${w}\n`);
    process.exitCode = exitCode;
  } catch (err) {
    const failClosed = config?.failClosed === true;
    process.stderr.write(`agent-guard internal error: ${err?.message || err}\n`);
    if (process.env.AGENT_GUARD_DEBUG) process.stderr.write(`${err?.stack}\n`);
    if (failClosed) {
      process.stderr.write('agent-guard is configured to fail closed; blocking this action.\n');
      process.exitCode = 2;
    } else {
      process.exitCode = 0;
    }
  }
}

const LABEL = { allow: 'ALLOW', ask: 'ASK  ', deny: 'DENY ' };

function cmdCheck(args) {
  const opts = parseOpts(args, ['--cwd']);
  const command = opts._.join(' ');
  if (!command) {
    console.error('usage: agent-guard check "<shell command>" [--cwd DIR] [--json]');
    process.exitCode = 64;
    return;
  }
  const cwd = resolve(opts['--cwd'] ?? process.cwd());
  const { ctx, warnings } = buildContext({ cwd });
  const result = evaluate({ tool_name: 'Bash', tool_input: { command }, cwd }, ctx);
  if (opts['--json']) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`${LABEL[result.decision]} ${command}`);
    for (const f of result.findings) console.log(`  - [${f.level}] ${f.rule}: ${f.reason}`);
    for (const w of warnings) console.log(`  ! ${w}`);
  }
  process.exitCode = result.decision === 'deny' ? 2 : result.decision === 'ask' ? 1 : 0;
}

function walk(dir, out, depth = 0) {
  if (depth > 12) return;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (['.git', 'node_modules', 'dist', 'build', '.next', 'coverage', 'vendor'].includes(entry.name)) continue;
    const p = join(dir, entry.name);
    if (entry.isDirectory()) walk(p, out, depth + 1);
    else if (entry.isFile()) out.push(p);
  }
}

function cmdScan(args) {
  const opts = parseOpts(args, []);
  const files = new Map();
  if (opts['--staged']) {
    const diff = execFileSync('git', ['diff', '--cached', '--no-color', '--no-ext-diff', '-U0'], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
    let cur = null;
    for (const line of diff.split('\n')) {
      if (line.startsWith('+++ ')) { cur = line.slice(4).replace(/^b\//, ''); if (cur !== '/dev/null') files.set(cur, []); continue; }
      if (cur && line.startsWith('+') && !line.startsWith('+++')) files.get(cur)?.push(line.slice(1));
    }
  } else {
    const targets = opts._.length ? opts._ : ['.'];
    const list = [];
    for (const t of targets) {
      if (!existsSync(t)) continue;
      if (statSync(t).isDirectory()) walk(t, list);
      else list.push(t);
    }
    for (const f of list) {
      try {
        if (statSync(f).size > 1024 * 1024) continue;
        const text = readFileSync(f, 'utf8');
        if (text.includes('\u0000')) continue; // binary
        files.set(f, [text]);
      } catch { /* skip */ }
    }
  }
  let high = 0;
  let medium = 0;
  for (const [file, chunks] of files) {
    for (const f of scanSecrets(chunks.join('\n'))) {
      if (f.confidence === 'high') high++; else medium++;
      console.log(`${f.confidence === 'high' ? 'SECRET ' : 'MAYBE  '} ${file}:${f.line}  ${f.name}  [${f.preview}]`);
    }
  }
  console.log(`\n${files.size} file(s) scanned: ${high} high-confidence, ${medium} possible secret(s).`);
  process.exitCode = high ? 1 : 0;
}

function cmdRules(args) {
  const json = args.includes('--json');
  if (json) {
    console.log(JSON.stringify(ALL_RULES.map(({ id, description }) => ({ id, description })), null, 2));
    return;
  }
  const seen = new Set();
  for (const r of ALL_RULES) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    console.log(`${r.id.padEnd(28)} ${r.description}`);
  }
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

const CLAUDE_MATCHER = 'Bash|Write|Edit|MultiEdit|NotebookEdit|Read';
const CODEX_MATCHER = 'Bash|apply_patch';

function hookCommand() {
  return `node "${join(ROOT, 'bin', 'agent-guard.mjs')}" hook`;
}

function mergeHooks(existing, matcher, extra = {}) {
  const doc = existing && typeof existing === 'object' ? existing : {};
  doc.hooks = doc.hooks && typeof doc.hooks === 'object' ? doc.hooks : {};
  const groups = Array.isArray(doc.hooks.PreToolUse) ? doc.hooks.PreToolUse : [];
  // remove previous agent-guard handlers (idempotent install)
  const cleaned = groups
    .map((g) => ({ ...g, hooks: (g.hooks || []).filter((h) => !String(h.command || '').includes('agent-guard')) }))
    .filter((g) => g.hooks.length);
  cleaned.push({ matcher, hooks: [{ type: 'command', command: hookCommand(), timeout: 15, ...extra }] });
  doc.hooks.PreToolUse = cleaned;
  return doc;
}

function cmdInstall(args) {
  const opts = parseOpts(args, []);
  const target = opts._[0];
  if (target !== 'claude' && target !== 'codex') {
    console.error('usage: agent-guard install <claude|codex> [--project] [--dry-run]');
    process.exitCode = 64;
    return;
  }
  const home = process.env.HOME || homedir();
  const base = opts['--project'] ? process.cwd() : home;
  const file = target === 'claude'
    ? join(base, '.claude', 'settings.json')
    : join(base, '.codex', 'hooks.json');
  let existing = {};
  if (existsSync(file)) {
    try {
      existing = JSON.parse(readFileSync(file, 'utf8'));
    } catch (err) {
      console.error(`Cannot parse ${file}: ${err.message}. Fix or remove it first.`);
      process.exitCode = 1;
      return;
    }
  }
  const merged = target === 'claude'
    ? mergeHooks(existing, CLAUDE_MATCHER)
    : mergeHooks(existing, CODEX_MATCHER, { statusMessage: 'agent-guard: checking' });
  const text = JSON.stringify(merged, null, 2) + '\n';
  if (opts['--dry-run']) {
    console.log(`# would write ${file}\n${text}`);
    return;
  }
  mkdirSync(dirname(file), { recursive: true });
  if (existsSync(file)) {
    const backup = `${file}.bak-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    copyFileSync(file, backup);
    console.log(`Backed up ${file} → ${backup}`);
  }
  writeFileSync(file, text);
  console.log(`agent-guard hook installed in ${file}`);
  if (target === 'codex') {
    console.log('Next: open Codex and run /hooks to review and trust the new hook (Codex skips untrusted hooks).');
  } else {
    console.log('Next: start a new Claude Code session (or run /hooks) to load it.');
  }
}

function cmdDoctor() {
  const cwd = process.cwd();
  const { ctx, warnings, sources } = buildContext({ cwd });
  console.log(`agent-guard ${PKG.version}  (node ${process.version})`);
  console.log(`project dir:     ${ctx.projectDir}`);
  console.log(`user config:     ${userConfigPath()}${existsSync(userConfigPath()) ? '' : ' (not present)'}`);
  const pc = projectConfigPath(ctx.projectDir);
  console.log(`project config:  ${pc}${existsSync(pc) ? '' : ' (not present)'}`);
  console.log(`loaded:          ${sources.length ? sources.join(', ') : 'defaults only'}`);
  console.log(`mode:            ${ctx.config.mode}`);
  console.log(`audit log:       ${ctx.config.auditLog ? auditLogPath() : 'disabled'}`);
  console.log(`protected branches: ${ctx.config.protectedBranches.join(', ')}`);
  if (ctx.config.disable.length) console.log(`disabled rules:  ${ctx.config.disable.join(', ')}`);
  for (const w of warnings) console.log(`warning: ${w}`);
}

// ---------------------------------------------------------------------------

const BOOLEAN_FLAGS = new Set(['--json', '--staged', '--project', '--dry-run']);

function parseOpts(args, withValue) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (withValue.includes(a)) { out[a] = args[++i]; continue; }
    if (BOOLEAN_FLAGS.has(a)) { out[a] = true; continue; }
    out._.push(a);
  }
  return out;
}

function help() {
  console.log(`agent-guard ${PKG.version} — guard rails for AI coding agents (Claude Code, Codex)

Usage:
  agent-guard hook                       PreToolUse hook entry point (reads JSON on stdin)
  agent-guard check "<command>"          Show what the guard decides for a shell command
        [--cwd DIR] [--json]             exit code: 0 allow, 1 ask, 2 deny
  agent-guard scan [paths…] | --staged   Scan files or staged git changes for secrets
  agent-guard rules [--json]             List rules
  agent-guard install <claude|codex>     Add the hook to ~/.claude/settings.json or ~/.codex/hooks.json
        [--project] [--dry-run]
  agent-guard doctor                     Show configuration and environment
  agent-guard --version`);
}

const [, , command, ...rest] = process.argv;
switch (command) {
  case 'hook': cmdHook(); break;
  case 'check': cmdCheck(rest); break;
  case 'scan': cmdScan(rest); break;
  case 'rules': cmdRules(rest); break;
  case 'install': cmdInstall(rest); break;
  case 'doctor': cmdDoctor(); break;
  case '--version': case '-v': console.log(PKG.version); break;
  case undefined:
    if (!process.stdin.isTTY) cmdHook(); else help();
    break;
  default: help(); process.exitCode = command === '--help' || command === '-h' ? 0 : 64;
}
