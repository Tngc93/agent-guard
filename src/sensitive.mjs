import { basename } from './shell.mjs';

// Files that typically hold credentials. Reading them puts secrets into the
// model's context (and transcript); sending them anywhere is exfiltration.
const SECRET_FILE_RES = [
  /(^|\/)\.env$/,
  /(^|\/)\.env\.(?!example$|sample$|template$|dist$|defaults$|schema$)[^/]+$/,
  /(^|\/)[^/]+\.env$/,
  /(^|\/)\.envrc$/,
  /(^|\/)id_(rsa|dsa|ecdsa|ed25519)(_sk)?$/,
  /\.(pem|key|p12|pfx|jks|keystore|ppk)$/,
  /(^|\/)\.ssh\/(?!known_hosts$|config$|[^/]+\.pub$)[^/]+$/,
  /(^|\/)\.aws\/(credentials|config)$/,
  /(^|\/)\.azure\/(credentials|accessTokens\.json|msal_token_cache\.json)$/,
  /(^|\/)\.config\/gcloud\/(credentials\.db|access_tokens\.db|application_default_credentials\.json)$/,
  /(^|\/)\.kube\/config$/,
  /(^|\/)\.docker\/config\.json$/,
  /(^|\/)\.netrc$/,
  /(^|\/)\.pgpass$/,
  /(^|\/)\.npmrc$/,
  /(^|\/)\.pypirc$/,
  /(^|\/)\.git-credentials$/,
  /(^|\/)\.config\/gh\/hosts\.yml$/,
  /(^|\/)\.terraformrc$/,
  /(^|\/)terraform\.tfstate(\.backup)?$/,
  /(^|\/)(service[-_]?account|credentials|client_secret)[^/]*\.json$/i,
  /(^|\/)secrets?\.(json|ya?ml|toml)$/i,
  /(^|\/)\.secrets?(\/|$)/,
];

export function isSecretFile(path) {
  const p = String(path ?? '');
  if (!p) return false;
  return SECRET_FILE_RES.some((re) => re.test(p));
}

/** Env-style files are where secrets are supposed to live; writing them is fine. */
export function isEnvFile(path) {
  const b = basename(path);
  return b === '.env' || b.startsWith('.env.') || b.endsWith('.env') || b === '.envrc' || b === '.dev.vars';
}

/** Example/template files are committed — they must NOT contain real secrets. */
export function isTemplateEnvFile(path) {
  return /(^|\/)\.env\.(example|sample|template|dist|defaults)$/.test(String(path ?? ''));
}

// Files that configure the agent's own guard rails. Editing them silently would
// let an agent switch off its own safety checks.
const GUARD_CONFIG_RES = [
  /(^|\/)\.agent-guard\.json$/,
  /(^|\/)\.config\/agent-guard\//,
  /(^|\/)\.claude\/settings(\.local)?\.json$/,
  /(^|\/)\.claude\/hooks\//,
  /(^|\/)\.codex\/(hooks\.json|config\.toml)$/,
  /(^|\/)\.codex\/hooks\//,
  /(^|\/)managed-settings\.json$/,
];

export function isGuardConfigFile(path) {
  return GUARD_CONFIG_RES.some((re) => re.test(String(path ?? '')));
}

// Shell startup / persistence files.
const PERSISTENCE_RES = [
  /(^|\/)\.(bash_profile|bashrc|zshrc|zprofile|zshenv|profile|bash_login|login|cshrc|tcshrc)$/,
  /(^|\/)\.config\/fish\/config\.fish$/,
  /(^|\/)\.ssh\/authorized_keys$/,
  /(^|\/)Library\/LaunchAgents\//,
  /^\/Library\/Launch(Agents|Daemons)\//,
  /^\/etc\//,
  /(^|\/)\.git\/hooks\//,
];

export function isPersistenceFile(path) {
  return PERSISTENCE_RES.some((re) => re.test(String(path ?? '')));
}

export function isGitInternal(path) {
  return /(^|\/)\.git\/(?!hooks\/)/.test(String(path ?? '')) || /(^|\/)\.git$/.test(String(path ?? ''));
}

export function isScriptFile(path) {
  const p = String(path ?? '');
  return /\.(sh|bash|zsh|command|ps1)$/.test(p) || /(^|\/)(Makefile|Justfile|justfile|Taskfile\.ya?ml)$/.test(p);
}
