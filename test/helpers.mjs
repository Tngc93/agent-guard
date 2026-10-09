import { makeContext } from '../src/paths.mjs';
import { DEFAULT_CONFIG } from '../src/config.mjs';
import { evaluate } from '../src/engine.mjs';

export const HOME = '/home/tester';
export const PROJECT = '/home/tester/work/app';

export function ctx(overrides = {}) {
  const config = structuredClone({ ...DEFAULT_CONFIG, ...overrides });
  return { ...makeContext({ cwd: PROJECT, projectDir: PROJECT, env: { HOME } }), config, errors: [], skipGit: true };
}

export function bash(command, configOverrides) {
  return evaluate({ tool_name: 'Bash', tool_input: { command }, cwd: PROJECT }, ctx(configOverrides));
}

export function tool(tool_name, tool_input, configOverrides) {
  return evaluate({ tool_name, tool_input, cwd: PROJECT }, ctx(configOverrides));
}

// Deterministic pseudo-random strings so that test files never contain
// real-looking secret literals (which would trip GitHub push protection).
let seed = 42;
function rnd() {
  seed = (seed * 1103515245 + 12345) & 0x7fffffff;
  return seed / 0x7fffffff;
}
export function randomString(len, alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
  let s = '';
  for (let i = 0; i < len; i++) s += alphabet[Math.floor(rnd() * alphabet.length)];
  return s;
}

export const fake = {
  anthropic: () => ['sk', 'ant', 'api03', randomString(90, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_')].join('-'),
  openai: () => ['sk', 'proj', randomString(60)].join('-'),
  github: () => 'gh' + 'p_' + randomString(36),
  aws: () => 'AK' + 'IA' + randomString(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
  stripe: () => 'sk' + '_live_' + randomString(32),
  google: () => 'AI' + 'za' + randomString(35),
  slackWebhook: () => ['https://hooks.slack.com/services', 'T' + randomString(8, 'ABCDEFGHIJ0123456789'), 'B' + randomString(8, 'ABCDEFGHIJ0123456789'), randomString(24)].join('/'),
  pem: () => ['-----BEGIN', 'RSA PRIVATE KEY-----'].join(' ') + '\n' + randomString(64, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/') + '\n' + randomString(64, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/') + '\n-----END RSA PRIVATE KEY-----',
  dbUrl: () => `postgres://app_user:${randomString(20)}@db.prod.internal.example.net:5432/app`,
};
