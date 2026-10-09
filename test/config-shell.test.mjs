import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig } from '../src/config.mjs';
import { parse, unwrap } from '../src/shell.mjs';
import { bash } from './helpers.mjs';
import { toHookResponse, detectPlatform } from '../src/output.mjs';
import { DEFAULT_CONFIG } from '../src/config.mjs';

function setup({ user, project }) {
  const root = mkdtempSync(join(tmpdir(), 'ag-cfg-'));
  const home = join(root, 'home');
  const proj = join(root, 'proj');
  mkdirSync(join(home, '.config', 'agent-guard'), { recursive: true });
  mkdirSync(proj, { recursive: true });
  if (user) writeFileSync(join(home, '.config', 'agent-guard', 'config.json'), JSON.stringify(user));
  if (project) writeFileSync(join(proj, '.agent-guard.json'), typeof project === 'string' ? project : JSON.stringify(project));
  return loadConfig({ projectDir: proj, env: { HOME: home } });
}

test('defaults when no config exists', () => {
  const { config, sources } = setup({});
  assert.equal(config.mode, 'enforce');
  assert.deepEqual(sources, []);
});

test('untrusted project config can tighten but not loosen', () => {
  const { config, warnings } = setup({
    project: {
      mode: 'audit',
      disable: ['fs.rm-recursive'],
      allow: ['.*'],
      overrides: { 'git.force-push': 'allow', 'release.publish': 'deny' },
      deny: [{ pattern: 'kubectl .*prod', reason: 'no prod from agents' }],
      protectedBranches: ['staging'],
    },
  });
  assert.equal(config.mode, 'enforce');
  assert.deepEqual(config.disable, []);
  assert.deepEqual(config.allow, []);
  assert.equal(config.overrides['git.force-push'], undefined);
  assert.equal(config.overrides['release.publish'], 'deny');
  assert.equal(config.deny.length, 1);
  assert.ok(config.protectedBranches.includes('staging'));
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /loosen/);
});

test('user config can loosen and can trust the project config', () => {
  const { config } = setup({
    user: { trustProjectConfig: true, disable: ['release.*'] },
    project: { disable: ['git.skip-hooks'], mode: 'audit' },
  });
  assert.deepEqual(config.disable.sort(), ['git.skip-hooks', 'release.*']);
  assert.equal(config.mode, 'audit');
});

test('invalid JSON is reported, not fatal', () => {
  const { config, warnings } = setup({ project: '{ not json' });
  assert.equal(config.mode, 'enforce');
  assert.match(warnings[0], /invalid project config/);
});

test('disable / overrides / custom patterns change decisions', () => {
  assert.equal(bash('npm publish', { disable: ['release.*'] }).decision, 'allow');
  assert.equal(bash('npm publish', { overrides: { 'release.publish': 'deny' } }).decision, 'deny');
  assert.equal(bash('git reset --hard', { overrides: { 'git.discard-work': 'allow' } }).decision, 'allow');
  assert.equal(bash('kubectl apply -f k8s/', { deny: [{ pattern: '^kubectl apply' }] }).decision, 'deny');
  assert.equal(bash('make deploy', { ask: [{ pattern: '^make deploy', reason: 'deploys' }] }).decision, 'ask');
  assert.equal(bash('rm -rf ./generated/*', { allow: ['^rm -rf \\./generated/\\*$'] }).decision, 'allow');
  assert.equal(bash('git push -f origin staging', { protectedBranches: ['staging'] }).decision, 'deny');
});

// ---- shell parser

test('parser: operators, pipelines, assignments, redirects', () => {
  const { commands } = parse('FOO=1 BAR=2 a b | c >out.txt 2>&1 && d; e &');
  assert.deepEqual(commands.map((c) => c.argv), [['a', 'b'], ['c'], ['d'], ['e']]);
  assert.deepEqual(commands[0].env, { FOO: '1', BAR: '2' });
  assert.equal(commands[0].pipeline, commands[1].pipeline);
  assert.notEqual(commands[1].pipeline, commands[2].pipeline);
  assert.deepEqual(commands[1].redirects.map((r) => [r.op, r.target]), [['>', 'out.txt'], ['>&', '1']]);
});

test('parser: quotes and escapes', () => {
  const { commands } = parse(`echo 'a b' "c \\"d\\"" e\\ f`);
  assert.deepEqual(commands[0].argv, ['echo', 'a b', 'c "d"', 'e f']);
});

test('parser: substitutions are surfaced', () => {
  const { nested } = parse('echo "$(whoami)" `date` <(ls)');
  assert.deepEqual(nested, ['whoami', 'date', 'ls']);
});

test('parser: heredoc body is data, not commands', () => {
  const { commands } = parse("cat > notes.md <<'EOF'\nrm -rf /\nEOF\nls");
  assert.deepEqual(commands.map((c) => c.argv), [['cat'], ['ls']]);
  assert.equal(commands[0].heredocs[0].body, 'rm -rf /');
});

test('parser: comments are ignored', () => {
  assert.deepEqual(parse('ls # rm -rf /').commands.map((c) => c.argv), [['ls']]);
});

test('unwrap: sudo/env/timeout/xargs/bash -c', () => {
  assert.deepEqual(unwrap(['sudo', '-u', 'root', '-E', 'rm', '-rf', 'x']).argv, ['rm', '-rf', 'x']);
  assert.deepEqual(unwrap(['env', '-i', 'A=1', 'node', 'x.js']).argv, ['node', 'x.js']);
  assert.deepEqual(unwrap(['timeout', '-s', 'KILL', '30', 'npm', 'test']).argv, ['npm', 'test']);
  assert.deepEqual(unwrap(['xargs', '-0', '-n', '1', 'rm', '-f']).argv, ['rm', '-f']);
  assert.equal(unwrap(['bash', '-lc', 'echo hi']).inner, 'echo hi');
  assert.equal(unwrap(['ssh', '-p', '22', 'host', 'rm', '-rf', '/srv']).inner, 'rm -rf /srv');
  assert.deepEqual(unwrap(['env']).argv, ['env']);
  assert.deepEqual(unwrap(['command', '-v', 'node']).argv, []);
});

// ---- output adaptation

test('platform detection', () => {
  assert.equal(detectPlatform({ turn_id: 'x', tool_name: 'Bash' }, {}), 'codex');
  assert.equal(detectPlatform({ tool_name: 'Bash' }, {}), 'claude');
  assert.equal(detectPlatform({ tool_name: 'Bash' }, { AGENT_GUARD_PLATFORM: 'codex' }), 'codex');
});

test('Claude gets ask; Codex gets deny (or allow when configured)', () => {
  const result = bash('git reset --hard');
  const cfg = structuredClone(DEFAULT_CONFIG);
  const claude = JSON.parse(toHookResponse(result, { platform: 'claude', config: cfg }).stdout);
  assert.equal(claude.hookSpecificOutput.permissionDecision, 'ask');
  const codex = JSON.parse(toHookResponse(result, { platform: 'codex', config: cfg }).stdout);
  assert.equal(codex.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(codex.hookSpecificOutput.permissionDecisionReason, /ask the user/);
  assert.equal(toHookResponse(result, { platform: 'codex', config: { ...cfg, codexAskBehavior: 'allow' } }).stdout, '');
});

test('audit mode never blocks', () => {
  const result = bash('rm -rf /');
  assert.equal(result.decision, 'deny');
  assert.equal(toHookResponse(result, { platform: 'claude', config: { ...structuredClone(DEFAULT_CONFIG), mode: 'audit' } }).stdout, '');
});
