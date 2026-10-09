// Secret detection.
//
// Two tiers:
//  - high confidence: provider-specific formats (vendor prefixes, PEM blocks).
//    These produce `deny`.
//  - heuristic: `password = "..."`-style assignments with a high-entropy value.
//    These produce `ask`, because they have a real false-positive rate.
//
// Values are never returned in full; callers get a redacted preview only.

const HIGH_CONFIDENCE = [
  { id: 'private-key', name: 'Private key block', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
  { id: 'aws-access-key', name: 'AWS access key ID', re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { id: 'aws-secret-key', name: 'AWS secret access key', re: /aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/gi, group: 1 },
  { id: 'github-token', name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { id: 'github-pat', name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{60,255}\b/g },
  { id: 'gitlab-token', name: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'anthropic-key', name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{30,}/g },
  { id: 'openai-key', name: 'OpenAI API key', re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{30,}/g },
  { id: 'openai-key-legacy', name: 'OpenAI API key', re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g },
  { id: 'google-api-key', name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'google-oauth-secret', name: 'Google OAuth client secret', re: /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g },
  { id: 'stripe-live-key', name: 'Stripe live key', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b/g },
  { id: 'slack-token', name: 'Slack token', re: /\bxox[abposr]-[0-9A-Za-z-]{10,}\b/g },
  { id: 'slack-webhook', name: 'Slack webhook URL', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,}/g },
  { id: 'discord-webhook', name: 'Discord webhook URL', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{15,}\/[A-Za-z0-9_-]{50,}/g },
  { id: 'npm-token', name: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'pypi-token', name: 'PyPI token', re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g },
  { id: 'huggingface-token', name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{34,}\b/g },
  { id: 'sendgrid-key', name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: 'telegram-bot-token', name: 'Telegram bot token', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { id: 'digitalocean-token', name: 'DigitalOcean token', re: /\bdo[opr]_v1_[a-f0-9]{64}\b/g },
  { id: 'shopify-token', name: 'Shopify access token', re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g },
];

const DB_URL_RE = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver):\/\/([^:\s/@'"]+):([^@\s'"]{3,})@([^\s/:'"?]+)/gi;

const GENERIC_ASSIGNMENT_RE = /\b([A-Za-z0-9_.-]*(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|client[_-]?secret|access[_-]?key|private[_-]?key|auth)[A-Za-z0-9_.-]*)["']?\s*(?::=|=|:|=>)\s*["']([^"'\s]{16,})["']/gi;

const PLACEHOLDER_HINTS = [
  'example', 'xxxx', 'your', 'changeme', 'change_me', 'placeholder', 'dummy', 'sample', 'redacted',
  '<', '>', '${', '{{', '%(', 'process.env', 'os.environ', 'getenv', 'env(', '****', '....', 'insert', 'replace',
  'todo', 'fixme', 'fake', 'mock', 'notreal', 'not-a-real', 'secret_here', 'token_here', 'here',
];

const LOCAL_DB_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1', 'db', 'database', 'postgres', 'mysql', 'mongo', 'mongodb', 'redis', 'host.docker.internal']);

const IGNORE_PRAGMA = /agent-guard:\s*allow|pragma:\s*allowlist secret|gitleaks:allow/i;

export function shannonEntropy(str) {
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function looksLikePlaceholder(value, { strict = false } = {}) {
  const v = String(value).toLowerCase();
  if (PLACEHOLDER_HINTS.some((hint) => v.includes(hint))) return true;
  if (/^(.)\1+$/.test(v)) return true; // aaaaaaa
  // For free-form values (heuristic tier) also skip word-ish strings.
  if (!strict && /^[a-z_]+$/.test(v) && v.length < 24) return true;
  return false;
}

export function redact(value) {
  const s = String(value);
  if (s.length <= 8) return '****';
  return `${s.slice(0, 4)}…${s.slice(-2)} (${s.length} chars)`;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

function lineText(text, index) {
  const start = text.lastIndexOf('\n', index - 1) + 1;
  const end = text.indexOf('\n', index);
  return text.slice(start, end === -1 ? text.length : end);
}

/**
 * Scan text for secrets.
 * @returns {Array<{id, name, confidence: 'high'|'medium', line, preview}>}
 */
export function scanSecrets(text, { includeHeuristic = true } = {}) {
  const findings = [];
  if (!text || typeof text !== 'string') return findings;
  const seen = new Set();

  const push = (f, index) => {
    const ln = lineText(text, index);
    if (IGNORE_PRAGMA.test(ln)) return;
    const key = `${f.id}:${f.line}:${f.preview}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };

  for (const det of HIGH_CONFIDENCE) {
    det.re.lastIndex = 0;
    let m;
    while ((m = det.re.exec(text)) !== null) {
      const value = det.group ? m[det.group] : m[0];
      if (det.id !== 'private-key' && looksLikePlaceholder(value, { strict: true })) continue;
      if (det.id === 'private-key') {
        // Require some key material after the header to avoid flagging docs.
        const after = text.slice(m.index + m[0].length, m.index + m[0].length + 200);
        if (!/[A-Za-z0-9+/=]{40,}/.test(after.replace(/\s+/g, ''))) continue;
      }
      push({ id: det.id, name: det.name, confidence: 'high', line: lineOf(text, m.index), preview: redact(value) }, m.index);
    }
  }

  DB_URL_RE.lastIndex = 0;
  let m;
  while ((m = DB_URL_RE.exec(text)) !== null) {
    const [, user, pass, host] = m;
    if (LOCAL_DB_HOSTS.has(host.toLowerCase())) continue;
    if (looksLikePlaceholder(pass) || pass === user || pass.startsWith('$')) continue;
    push({ id: 'database-url-password', name: 'Database URL with password', confidence: 'high', line: lineOf(text, m.index), preview: `${m[0].split('://')[0]}://${user}:${redact(pass)}@${host}` }, m.index);
  }

  if (includeHeuristic) {
    GENERIC_ASSIGNMENT_RE.lastIndex = 0;
    while ((m = GENERIC_ASSIGNMENT_RE.exec(text)) !== null) {
      const [, key, value] = m;
      if (looksLikePlaceholder(value)) continue;
      if (/^[A-Z0-9_]+$/.test(value) && value.length < 32) continue; // ENV_VAR_NAME references
      if (/^(?:https?:)?\/\//.test(value) && !/[?&](?:key|token|secret)=/i.test(value)) continue;
      if (shannonEntropy(value) < 3.5) continue;
      // Skip if already covered by a high-confidence finding on the same line.
      const line = lineOf(text, m.index);
      if (findings.some((f) => f.line === line && f.confidence === 'high')) continue;
      push({ id: 'generic-secret', name: `Hard-coded secret in "${key}"`, confidence: 'medium', line, preview: redact(value) }, m.index);
    }
  }

  return findings;
}

/** Remove secret values from arbitrary text (used for audit logs). */
export function redactSecretsInText(text) {
  if (!text || typeof text !== 'string') return text;
  let out = text;
  for (const det of HIGH_CONFIDENCE) {
    det.re.lastIndex = 0;
    out = out.replace(det.re, (match) => (det.id === 'private-key' ? match : redact(match)));
  }
  out = out.replace(DB_URL_RE, (match, user, pass) => match.replace(`:${pass}@`, ':****@'));
  return out;
}
