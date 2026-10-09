// Configuration loading with a trust model.
//
// Two layers:
//   user    ~/.config/agent-guard/config.json   (or $AGENT_GUARD_CONFIG)
//   project <project>/.agent-guard.json
//
// The project file lives inside the repository the agent is working on, so the
// agent (or a malicious repo you cloned) could write to it. Therefore the
// project layer may only TIGHTEN policy (add deny/ask rules, protected paths,
// protected branches) unless the user layer sets "trustProjectConfig": true.
// Loosening keys (disable, overrides to "allow", allow patterns, mode) from an
// untrusted project file are ignored and reported.

import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const DEFAULT_CONFIG = Object.freeze({
  mode: 'enforce', // 'enforce' | 'audit' (audit = log only, never block)
  disable: [], // rule ids to turn off
  overrides: {}, // { ruleId: 'deny' | 'ask' | 'allow' }
  allow: [], // regexes matched against the full shell command → always allow
  deny: [], // [{ pattern, reason }] extra shell regexes → deny
  ask: [], // [{ pattern, reason }] extra shell regexes → ask
  protectedPaths: [], // extra globs that need approval to write
  protectedBranches: ['main', 'master', 'production', 'prod', 'release', 'release/*'],
  codexAskBehavior: 'deny', // Codex has no "ask": 'deny' (safe default) or 'allow'
  auditLog: true,
  failClosed: false, // on internal error: false → allow (fail open), true → block
  trustProjectConfig: false,
});

const LOOSENING_KEYS = ['disable', 'overrides', 'allow', 'mode', 'failClosed', 'codexAskBehavior', 'auditLog', 'trustProjectConfig'];

function readJson(path) {
  try {
    if (!existsSync(path)) return null;
    const raw = readFileSync(path, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return { __error: `${path}: ${err.message}` };
  }
}

export function userConfigPath(env = process.env) {
  if (env.AGENT_GUARD_CONFIG) return env.AGENT_GUARD_CONFIG;
  const base = env.XDG_CONFIG_HOME || join(env.HOME || homedir(), '.config');
  return join(base, 'agent-guard', 'config.json');
}

export function projectConfigPath(projectDir) {
  return projectDir ? join(projectDir, '.agent-guard.json') : null;
}

function asArray(v) {
  return Array.isArray(v) ? v : v == null ? [] : [v];
}

function normalizePatternRules(list) {
  return asArray(list)
    .map((r) => (typeof r === 'string' ? { pattern: r } : r))
    .filter((r) => r && typeof r.pattern === 'string');
}

/**
 * Merge user + project config.
 * @returns {{ config, warnings: string[], sources: string[] }}
 */
export function loadConfig({ projectDir, env = process.env } = {}) {
  const warnings = [];
  const sources = [];
  const config = structuredClone({ ...DEFAULT_CONFIG });

  const userPath = userConfigPath(env);
  const user = readJson(userPath);
  if (user?.__error) warnings.push(`Ignoring invalid user config ${user.__error}`);
  else if (user) {
    sources.push(userPath);
    applyLayer(config, user, { trusted: true });
  }

  const projectPath = projectConfigPath(projectDir);
  const project = projectPath ? readJson(projectPath) : null;
  if (project?.__error) warnings.push(`Ignoring invalid project config ${project.__error}`);
  else if (project) {
    sources.push(projectPath);
    const trusted = config.trustProjectConfig === true;
    const ignored = applyLayer(config, project, { trusted });
    if (ignored.length) {
      warnings.push(
        `Project config ${projectPath} tried to loosen policy (${ignored.join(', ')}); ignored. ` +
          `Set "trustProjectConfig": true in ${userPath} to allow this.`,
      );
    }
  }

  return { config, warnings, sources };
}

function applyLayer(config, layer, { trusted }) {
  const ignored = [];
  for (const key of Object.keys(layer)) {
    if (key.startsWith('$') || key === 'comment') continue;
    if (!trusted && LOOSENING_KEYS.includes(key)) {
      // `overrides` may still tighten (set a rule to deny/ask) from an untrusted layer.
      if (key === 'overrides' && layer.overrides && typeof layer.overrides === 'object') {
        for (const [id, level] of Object.entries(layer.overrides)) {
          if (level === 'deny' || level === 'ask') config.overrides[id] = level;
          else ignored.push(`overrides.${id}=${level}`);
        }
        continue;
      }
      if (key === 'mode' && layer.mode === 'enforce') continue;
      ignored.push(key);
      continue;
    }
    switch (key) {
      case 'disable':
        config.disable = [...new Set([...config.disable, ...asArray(layer.disable)])];
        break;
      case 'overrides':
        Object.assign(config.overrides, layer.overrides || {});
        break;
      case 'allow':
        config.allow = [...config.allow, ...asArray(layer.allow).filter((x) => typeof x === 'string')];
        break;
      case 'deny':
        config.deny = [...config.deny, ...normalizePatternRules(layer.deny)];
        break;
      case 'ask':
        config.ask = [...config.ask, ...normalizePatternRules(layer.ask)];
        break;
      case 'protectedPaths':
        config.protectedPaths = [...new Set([...config.protectedPaths, ...asArray(layer.protectedPaths)])];
        break;
      case 'protectedBranches':
        config.protectedBranches = [...new Set([...config.protectedBranches, ...asArray(layer.protectedBranches)])];
        break;
      case 'mode':
        if (layer.mode === 'enforce' || layer.mode === 'audit') config.mode = layer.mode;
        break;
      case 'codexAskBehavior':
        if (layer.codexAskBehavior === 'deny' || layer.codexAskBehavior === 'allow') config.codexAskBehavior = layer.codexAskBehavior;
        break;
      case 'auditLog':
      case 'failClosed':
      case 'trustProjectConfig':
        config[key] = layer[key] === true;
        break;
      default:
        break;
    }
  }
  return ignored;
}
