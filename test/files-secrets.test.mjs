import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tool, bash, fake, PROJECT } from './helpers.mjs';
import { scanSecrets, redactSecretsInText, shannonEntropy } from '../src/secrets.mjs';
import { parseApplyPatch } from '../src/rules/files.mjs';

const write = (file_path, content) => tool('Write', { file_path, content });

test('detects provider keys with high confidence', () => {
  for (const [name, make] of Object.entries(fake)) {
    const value = make();
    const found = scanSecrets(`const x = "${value}";`);
    assert.ok(found.some((f) => f.confidence === 'high'), `${name} not detected: ${value.slice(0, 12)}…`);
    // never leaks the full value
    for (const f of found) assert.ok(!f.preview.includes(value), `${name} preview leaks the secret`);
  }
});

test('ignores placeholders, env references and doc examples', () => {
  const samples = [
    'apiKey: process.env.ANTHROPIC_API_KEY',
    'OPENAI_API_KEY=your-api-key-here',
    'const token = "<YOUR_TOKEN>"',
    'password = "changeme-please-123"',
    'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
    'DATABASE_URL=postgres://postgres:postgres@localhost:5432/app',
    'DATABASE_URL=postgres://user:${DB_PASSWORD}@db.example.com/app',
    'secret: "xxxxxxxxxxxxxxxxxxxxxxxx"',
    '-----BEGIN RSA PRIVATE KEY----- (truncated in docs)',
  ];
  for (const s of samples) assert.deepEqual(scanSecrets(s), [], `false positive on: ${s}`);
});

test('heuristic assignments are medium confidence', () => {
  const value = 'Zq8vX2pL' + '0rT6yW1nB4mK9cJ3';
  const found = scanSecrets(`const config = { client_secret: "${value}" }`);
  assert.equal(found.length, 1);
  assert.equal(found[0].confidence, 'medium');
});

test('inline allow pragma suppresses a finding', () => {
  assert.deepEqual(scanSecrets(`const k = "${fake.github()}"; // agent-guard: allow`), []);
});

test('redactSecretsInText removes values', () => {
  const key = fake.anthropic();
  const out = redactSecretsInText(`curl -H "x-api-key: ${key}"`);
  assert.ok(!out.includes(key));
});

test('entropy helper', () => {
  assert.ok(shannonEntropy('aaaaaaaa') < 0.1);
  assert.ok(shannonEntropy('Zq8vX2pL0rT6yW1nB4mK') > 3.5);
});

// ---- Write / Edit / MultiEdit

test('Write: hard-coded key in source → deny', () => {
  const r = write(`${PROJECT}/src/client.ts`, `export const client = new Anthropic({ apiKey: "${fake.anthropic()}" })`);
  assert.equal(r.decision, 'deny');
  assert.equal(r.findings[0].rule, 'secrets.hardcoded');
});

test('Write: key into .env → allow; into .env.example → deny', () => {
  assert.equal(write(`${PROJECT}/.env`, `OPENAI_API_KEY=${fake.openai()}`).decision, 'allow');
  assert.equal(write(`${PROJECT}/.env.local`, `GITHUB_TOKEN=${fake.github()}`).decision, 'allow');
  assert.equal(write(`${PROJECT}/.env.example`, `GITHUB_TOKEN=${fake.github()}`).decision, 'deny');
});

test('Edit / MultiEdit scan new content only', () => {
  const key = fake.stripe();
  assert.equal(tool('Edit', { file_path: `${PROJECT}/a.js`, old_string: `const k = "${key}"`, new_string: 'const k = process.env.STRIPE_KEY' }).decision, 'allow');
  assert.equal(tool('Edit', { file_path: `${PROJECT}/a.js`, old_string: 'x', new_string: `const k = "${key}"` }).decision, 'deny');
  assert.equal(tool('MultiEdit', { file_path: `${PROJECT}/a.js`, edits: [{ old_string: 'a', new_string: 'b' }, { old_string: 'c', new_string: fake.pem() }] }).decision, 'deny');
});

test('Write: guard/agent config and persistence files → ask', () => {
  for (const p of [`${PROJECT}/.agent-guard.json`, `${PROJECT}/.claude/settings.json`, `${PROJECT}/.claude/settings.local.json`, `${PROJECT}/.codex/hooks.json`, '/home/tester/.zshrc', '/home/tester/.ssh/authorized_keys']) {
    const r = write(p, '{}');
    assert.equal(r.decision, 'ask', p);
    assert.equal(r.findings[0].rule, 'fs.protected-write');
  }
});

test('Write: git internals and system paths → deny', () => {
  assert.equal(write(`${PROJECT}/.git/config`, '[core]').decision, 'deny');
  assert.equal(write('/usr/local/bin/node', 'x').decision, 'deny');
  assert.equal(write(`${PROJECT}/.git/hooks/pre-commit`, '#!/bin/sh\nexit 0').decision, 'ask');
});

test('Write: ordinary files → allow', () => {
  assert.equal(write(`${PROJECT}/src/index.ts`, 'export const x = 1;').decision, 'allow');
  assert.equal(write(`${PROJECT}/README.md`, 'Run `rm -rf node_modules` to reset.').decision, 'allow');
});

test('Write: script containing a catastrophic command → ask', () => {
  const r = write(`${PROJECT}/scripts/clean.sh`, '#!/bin/bash\nset -e\nrm -rf "$HOME"/\n');
  assert.equal(r.decision, 'ask');
  assert.equal(r.findings[0].rule, 'exec.script-content');
  assert.equal(write(`${PROJECT}/scripts/clean.sh`, '#!/bin/bash\nrm -rf dist\n').decision, 'allow');
});

test('protectedPaths config', () => {
  const r = tool('Write', { file_path: `${PROJECT}/migrations/001_init.sql`, content: 'x' }, { protectedPaths: ['migrations/**'] });
  assert.equal(r.decision, 'ask');
});

test('Read: credential files → ask; normal files → allow', () => {
  assert.equal(tool('Read', { file_path: `${PROJECT}/.env` }).decision, 'ask');
  assert.equal(tool('Read', { file_path: '/home/tester/.aws/credentials' }).decision, 'ask');
  assert.equal(tool('Read', { file_path: `${PROJECT}/certs/server.key` }).decision, 'ask');
  assert.equal(tool('Read', { file_path: `${PROJECT}/.env.example` }).decision, 'allow');
  assert.equal(tool('Read', { file_path: `${PROJECT}/src/env.ts` }).decision, 'allow');
});

// ---- Codex apply_patch

test('parseApplyPatch', () => {
  const changes = parseApplyPatch(['*** Begin Patch', '*** Add File: a.txt', '+hello', '*** Update File: b.js', '*** Move to: c.js', '@@', '-old', '+new', '*** Delete File: d.md', '*** End Patch'].join('\n'));
  assert.deepEqual(changes.map((c) => [c.op, c.path, c.content]), [
    ['write', 'a.txt', 'hello'],
    ['edit', 'c.js', 'new'],
    ['move', 'b.js', ''],
    ['delete', 'd.md', ''],
  ]);
});

test('apply_patch: secret → deny, guard config → ask, normal → allow', () => {
  const patch = (body) => ({ command: `*** Begin Patch\n${body}\n*** End Patch` });
  assert.equal(tool('apply_patch', patch(`*** Add File: src/config.ts\n+export const key = "${fake.aws()}";`)).decision, 'deny');
  assert.equal(tool('apply_patch', patch('*** Delete File: .agent-guard.json')).decision, 'ask');
  assert.equal(tool('apply_patch', patch('*** Update File: src/a.ts\n@@\n-a\n+b')).decision, 'allow');
});

// ---- shell writes containing secrets

test('shell heredoc/echo writing a key into a source file → deny', () => {
  assert.equal(bash(`cat > src/keys.ts <<EOF\nexport const k = "${fake.openai()}";\nEOF`).decision, 'deny');
  assert.equal(bash(`echo "TOKEN=${fake.github()}" >> config.yml`).decision, 'deny');
  assert.equal(bash(`echo "TOKEN=${fake.github()}" >> .env`).decision, 'allow');
});
