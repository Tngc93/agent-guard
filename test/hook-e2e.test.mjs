import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fake } from './helpers.mjs';

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'agent-guard.mjs');

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), 'ag-e2e-'));
  const home = join(root, 'home');
  const proj = join(root, 'proj');
  mkdirSync(home, { recursive: true });
  mkdirSync(proj, { recursive: true });
  const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, '.config'), XDG_STATE_HOME: join(home, '.state'), CLAUDE_PROJECT_DIR: '', CLAUDE_PLUGIN_DATA: '', PLUGIN_DATA: '', AGENT_GUARD_CONFIG: '', AGENT_GUARD_PLATFORM: '' };
  return { root, home, proj, env };
}

function runHook(payload, env) {
  const res = spawnSync(process.execPath, [BIN, 'hook'], { input: typeof payload === 'string' ? payload : JSON.stringify(payload), env, encoding: 'utf8' });
  return { code: res.status, stdout: res.stdout.trim(), stderr: res.stderr, json: res.stdout.trim() ? JSON.parse(res.stdout) : null };
}

test('hook: allow produces no output and exit 0', () => {
  const { proj, env } = sandbox();
  const r = runHook({ session_id: 's', cwd: proj, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'npm test' } }, env);
  assert.equal(r.code, 0);
  assert.equal(r.stdout, '');
});

test('hook: Claude deny/ask JSON contract', () => {
  const { proj, env } = sandbox();
  const deny = runHook({ cwd: proj, tool_name: 'Bash', tool_input: { command: 'rm -rf ~' } }, env);
  assert.equal(deny.code, 0);
  assert.equal(deny.json.hookSpecificOutput.hookEventName, 'PreToolUse');
  assert.equal(deny.json.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(deny.json.hookSpecificOutput.permissionDecisionReason, /fs\.rm-recursive/);

  const ask = runHook({ cwd: proj, tool_name: 'Bash', tool_input: { command: 'git reset --hard' } }, env);
  assert.equal(ask.json.hookSpecificOutput.permissionDecision, 'ask');
});

test('hook: Codex payload never receives "ask"', () => {
  const { proj, env } = sandbox();
  const r = runHook({ session_id: 's', turn_id: 't1', cwd: proj, hook_event_name: 'PreToolUse', model: 'x', tool_name: 'Bash', tool_use_id: 'u', tool_input: { command: 'git reset --hard' } }, env);
  assert.equal(r.json.hookSpecificOutput.permissionDecision, 'deny');
});

test('hook: malformed input fails open by default', () => {
  const { env } = sandbox();
  const r = runHook('{not json', env);
  assert.equal(r.code, 0);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, /internal error/);
});

test('hook: audit log is written for non-allow decisions, with secrets redacted', () => {
  const { home, proj, env } = sandbox();
  const key = fake.anthropic();
  runHook({ cwd: proj, tool_name: 'Bash', tool_input: { command: `echo "K=${key}" > src/k.ts` } }, env);
  const log = readFileSync(join(home, '.state', 'agent-guard', 'audit.jsonl'), 'utf8');
  const entry = JSON.parse(log.trim().split('\n').pop());
  assert.equal(entry.decision, 'deny');
  assert.ok(!log.includes(key), 'audit log must not contain the secret');
});

test('hook: project config cannot disable rules unless trusted', () => {
  const { home, proj, env } = sandbox();
  writeFileSync(join(proj, '.agent-guard.json'), JSON.stringify({ disable: ['fs.rm-recursive'] }));
  const r = runHook({ cwd: proj, tool_name: 'Bash', tool_input: { command: 'rm -rf ~' } }, env);
  assert.equal(r.json.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(r.stderr, /loosen/);

  mkdirSync(join(home, '.config', 'agent-guard'), { recursive: true });
  writeFileSync(join(home, '.config', 'agent-guard', 'config.json'), JSON.stringify({ trustProjectConfig: true }));
  const r2 = runHook({ cwd: proj, tool_name: 'Bash', tool_input: { command: 'rm -rf ~' } }, env);
  assert.equal(r2.stdout, '');
});

// ---- git commit scanning (real git repo)

function hasGit() {
  try {
    execFileSync('git', ['--version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

test('git commit: blocks staged secrets and credential files', { skip: !hasGit() }, () => {
  const { proj, env } = sandbox();
  const g = (...args) => execFileSync('git', args, { cwd: proj, env: { ...env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' }, stdio: 'ignore' });
  g('init', '-q');
  writeFileSync(join(proj, 'ok.js'), 'export const a = 1;\n');
  g('add', 'ok.js');
  let r = runHook({ cwd: proj, tool_name: 'Bash', tool_input: { command: 'git commit -m "ok"' } }, env);
  assert.equal(r.stdout, '', 'clean staged change should be allowed');

  writeFileSync(join(proj, 'client.js'), `const key = "${fake.github()}";\n`);
  g('add', 'client.js');
  r = runHook({ cwd: proj, tool_name: 'Bash', tool_input: { command: 'git commit -m "add client"' } }, env);
  assert.equal(r.json.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /git\.commit-secrets/);
  g('reset', '-q');

  // `git add . && git commit` — untracked files are scanned too
  writeFileSync(join(proj, '.env'), 'SECRET=1\n');
  r = runHook({ cwd: proj, tool_name: 'Bash', tool_input: { command: 'git add . && git commit -m wip' } }, env);
  assert.equal(r.json.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /credentials file/);
});

// ---- CLI

test('cli: check exit codes', () => {
  const { proj, env } = sandbox();
  const run = (cmd) => spawnSync(process.execPath, [BIN, 'check', cmd, '--cwd', proj], { env, encoding: 'utf8' }).status;
  assert.equal(run('ls -la'), 0);
  assert.equal(run('git reset --hard'), 1);
  assert.equal(run('rm -rf /'), 2);
});

test('cli: install --dry-run is idempotent and keeps other hooks', () => {
  const { home, env } = sandbox();
  mkdirSync(join(home, '.claude'), { recursive: true });
  writeFileSync(join(home, '.claude', 'settings.json'), JSON.stringify({ model: 'x', hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'other-tool' }] }] } }));
  const out = spawnSync(process.execPath, [BIN, 'install', 'claude'], { env, encoding: 'utf8' });
  assert.equal(out.status, 0, out.stderr);
  spawnSync(process.execPath, [BIN, 'install', 'claude'], { env, encoding: 'utf8' });
  const settings = JSON.parse(readFileSync(join(home, '.claude', 'settings.json'), 'utf8'));
  assert.equal(settings.model, 'x');
  const commands = settings.hooks.PreToolUse.flatMap((g) => g.hooks.map((h) => h.command));
  assert.equal(commands.filter((c) => c.includes('agent-guard')).length, 1);
  assert.ok(commands.includes('other-tool'));

  const codex = spawnSync(process.execPath, [BIN, 'install', 'codex'], { env, encoding: 'utf8' });
  assert.equal(codex.status, 0);
  assert.ok(existsSync(join(home, '.codex', 'hooks.json')));
});

test('cli: scan finds secrets in files', () => {
  const { proj, env } = sandbox();
  writeFileSync(join(proj, 'a.py'), `KEY = "${fake.google()}"\n`);
  writeFileSync(join(proj, 'b.py'), 'print("hello")\n');
  const r = spawnSync(process.execPath, [BIN, 'scan', proj], { env, encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stdout, /a\.py:1/);
  assert.doesNotMatch(r.stdout, /b\.py/);
});

test('cli: rules lists every rule id once', () => {
  const r = spawnSync(process.execPath, [BIN, 'rules', '--json'], { encoding: 'utf8' });
  const rules = JSON.parse(r.stdout);
  assert.ok(rules.length >= 20);
  assert.equal(new Set(rules.map((x) => x.id)).size, rules.length);
});
