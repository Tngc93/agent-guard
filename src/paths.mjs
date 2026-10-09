import { homedir, tmpdir } from 'node:os';
import { isAbsolute, normalize, resolve, sep } from 'node:path';

export function makeContext({ cwd, projectDir, env = process.env } = {}) {
  const home = env.HOME || homedir();
  const workdir = cwd || projectDir || process.cwd();
  const project = projectDir || workdir;
  const tmpRoots = [...new Set(['/tmp', '/private/tmp', '/var/tmp', '/var/folders', '/private/var/folders', tmpdir(), env.TMPDIR].filter(Boolean).map((p) => stripTrailing(normalize(p))))];
  return { home: stripTrailing(normalize(home)), cwd: stripTrailing(normalize(workdir)), projectDir: stripTrailing(normalize(project)), tmpRoots };
}

function stripTrailing(p) {
  return p.length > 1 && p.endsWith(sep) ? p.slice(0, -1) : p;
}

const VAR_RE = /\$(?:\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])/;

/**
 * Expand a path-like shell word as far as is safely knowable.
 * @returns {{ abs: string|null, hasVar: boolean, guardedVar: boolean, glob: boolean, raw: string }}
 */
export function expandPath(word, ctx) {
  const raw = String(word ?? '');
  let s = raw;
  if (s === '~' || s.startsWith('~/')) s = ctx.home + s.slice(1);
  s = s.replace(/\$\{HOME\}|\$HOME\b/g, ctx.home);
  s = s.replace(/\$\{PWD\}|\$PWD\b/g, ctx.cwd);
  const hasVar = VAR_RE.test(s);
  // ${VAR:?msg} aborts if VAR is empty — the classic safe pattern.
  const guardedVar = hasVar && /\$\{[A-Za-z_][A-Za-z0-9_]*:\?[^}]*\}/.test(s) && !/\$(?![{])[A-Za-z_]/.test(s);
  const glob = /[*?[]/.test(s);
  if (hasVar) return { abs: null, hasVar, guardedVar, glob, raw };
  const abs = stripTrailing(normalize(isAbsolute(s) ? s : resolve(ctx.cwd, s)));
  return { abs, hasVar: false, guardedVar: false, glob, raw };
}

export function isWithin(child, parent) {
  if (!child || !parent) return false;
  if (child === parent) return true;
  const p = parent.endsWith(sep) ? parent : parent + sep;
  return child.startsWith(p);
}

export function isTemp(abs, ctx) {
  return ctx.tmpRoots.some((t) => isWithin(abs, t) && abs !== t);
}

export function inProject(abs, ctx) {
  return isWithin(abs, ctx.projectDir) || isWithin(abs, ctx.cwd);
}

const SYSTEM_DIRS = [
  '/bin', '/boot', '/dev', '/etc', '/lib', '/lib32', '/lib64', '/opt', '/proc', '/root', '/sbin', '/srv', '/sys', '/usr', '/var',
  '/System', '/Library', '/Applications', '/private', '/Volumes', '/cores', '/snap',
];

/** True for paths whose recursive deletion would be catastrophic. */
export function isCatastrophicTarget(abs, ctx) {
  if (!abs) return false;
  if (abs === '/' || abs === ctx.home) return true;
  // Any ancestor of the home directory (/Users, /home)
  if (isWithin(ctx.home, abs)) return true;
  // System directories themselves or their first level (e.g. /usr, /usr/lib)
  for (const dir of SYSTEM_DIRS) {
    if (abs === dir) return true;
    if (isWithin(abs, dir) && !isTemp(abs, ctx)) {
      const rest = abs.slice(dir.length + 1);
      if (!rest.includes('/')) return true;
    }
  }
  // Top-level folders of $HOME that hold user data
  const homeData = ['Documents', 'Desktop', 'Downloads', 'Pictures', 'Music', 'Movies', 'Library', '.ssh', '.config', '.gnupg', '.aws'];
  for (const d of homeData) if (abs === `${ctx.home}/${d}`) return true;
  return false;
}

/** Minimal glob → RegExp (supports **, *, ?) for protectedPaths. */
export function globToRegExp(glob) {
  let re = '';
  const g = String(glob);
  for (let i = 0; i < g.length; i++) {
    const ch = g[i];
    if (ch === '*') {
      if (g[i + 1] === '*') {
        re += '.*';
        i++;
        if (g[i + 1] === '/') i++;
      } else re += '[^/]*';
    } else if (ch === '?') re += '[^/]';
    else re += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`(^|/)${re}$`);
}

export function matchesAnyGlob(path, globs) {
  return globs.some((g) => globToRegExp(g).test(path));
}
