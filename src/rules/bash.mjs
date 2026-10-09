// Shell command rules.
//
// Every rule receives a normalised view of ONE simple command:
//   view = {
//     name,        // basename of the real program after unwrapping sudo/env/…
//     args,        // arguments after the program name
//     rawArgs,     // original (quoted) source text of each argument
//     wrappers,    // e.g. ['sudo']
//     env,         // leading NAME=value assignments
//     redirects,   // [{ op, fd, target }]
//     pipeline,    // all commands of the same pipeline (views), in order
//     pipeIndex,   // this command's position in its pipeline
//   }
// and returns null, a finding, or an array of findings:
//   { rule, level: 'deny' | 'ask', reason }

import { flagSet, positionals, isShell, basename } from '../shell.mjs';
import { expandPath, isCatastrophicTarget, inProject, isTemp, isWithin, matchesAnyGlob } from '../paths.mjs';
import { isSecretFile, isGuardConfigFile, isPersistenceFile, isEnvFile } from '../sensitive.mjs';

const finding = (rule, level, reason) => ({ rule, level, reason });

const PROD_RE = /(^|[^a-z])(prod|production)([^a-z]|$)/i;

function mentionsProduction(view) {
  if (Object.values(view.env).some((v) => PROD_RE.test(v))) return true;
  return view.args.some((a) => PROD_RE.test(a));
}

function escalateOnProd(view, level) {
  return level === 'ask' && mentionsProduction(view) ? 'deny' : level;
}

const sub = (view, i = 0) => positionals(view.args)[i];

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

function rmTargets(view) {
  const flags = flagSet(view.args);
  const recursive = flags.has('r', '--recursive') || flags.has('R');
  const targets = positionals(view.args);
  return { recursive, force: flags.has('f', '--force'), targets, noPreserveRoot: flags.long.has('--no-preserve-root') };
}

function classifyDeleteTarget(word, raw, ctx) {
  const t = expandPath(word, ctx);
  const rawText = raw ?? word;
  if (t.hasVar) {
    // Strip a trailing /* or /** glob and look at the parent: "$HOME"/* etc.
    return t.guardedVar ? { kind: 'ok' } : { kind: 'unresolved', label: rawText };
  }
  const abs = t.abs;
  let parent = abs;
  if (t.glob) {
    // `/*`, `~/*`, `./*`, `*` → the effective scope is the parent directory
    const idx = abs.search(/[*?[]/);
    parent = abs.slice(0, idx).replace(/\/+$/, '') || '/';
  }
  if (isCatastrophicTarget(parent, ctx)) return { kind: 'catastrophic', label: rawText, abs: parent };
  if (parent === ctx.cwd || parent === ctx.projectDir) return { kind: 'project-root', label: rawText, abs: parent };
  if (/(^|\/)\.git$/.test(parent)) return { kind: 'git-dir', label: rawText, abs: parent };
  if (isTemp(parent, ctx)) return { kind: 'ok' };
  if (!inProject(parent, ctx)) return { kind: 'outside', label: rawText, abs: parent };
  return { kind: 'ok' };
}

const rmRule = {
  id: 'fs.rm-recursive',
  description: 'Recursive delete of /, $HOME, system folders (deny); of the project root, outside the project, .git, or an unverifiable $VAR path (ask)',
  check(view, ctx) {
    if (!['rm', 'rmdir', 'unlink', 'srm', 'trash-put'].includes(view.name)) return null;
    const { recursive, targets, noPreserveRoot } = rmTargets(view);
    if (noPreserveRoot) return finding('fs.rm-recursive', 'deny', '`rm --no-preserve-root` can wipe the whole filesystem.');
    if (view.name !== 'rm' || !recursive) return null;
    const out = [];
    const rawTargets = positionals(view.rawArgs);
    targets.forEach((t, i) => {
      const c = classifyDeleteTarget(t, rawTargets[i], ctx);
      if (c.kind === 'catastrophic') out.push(finding('fs.rm-recursive', 'deny', `Recursive delete of \`${c.label}\` would destroy ${c.abs === '/' ? 'the entire filesystem' : `\`${c.abs}\``}.`));
      else if (c.kind === 'unresolved') out.push(finding('fs.rm-recursive', 'ask', `Recursive delete of \`${c.label}\`: the path depends on a shell variable. If it is empty or unset this can target \`/\`. Use \`\${VAR:?}\` or an explicit path.`));
      else if (c.kind === 'project-root') out.push(finding('fs.rm-recursive', 'ask', `Recursive delete of \`${c.label}\` removes the whole project directory.`));
      else if (c.kind === 'git-dir') out.push(finding('fs.rm-recursive', 'ask', `Deleting \`${c.label}\` erases the repository history.`));
      else if (c.kind === 'outside') out.push(finding('fs.rm-recursive', 'ask', `Recursive delete outside the project: \`${c.abs}\`.`));
    });
    return out;
  },
};

const findDeleteRule = {
  id: 'fs.find-delete',
  description: '`find … -delete` / `-exec rm` starting at /, $HOME or a system folder (deny) or outside the project (ask)',
  check(view, ctx) {
    if (view.name !== 'find' && view.name !== 'fd') return null;
    const deletes = view.args.includes('-delete') || view.args.some((a, i) => (a === '-exec' || a === '-execdir' || a === '-x' || a === '--exec') && /^(\/bin\/)?rm$/.test(view.args[i + 1] ?? ''));
    if (!deletes) return null;
    const roots = [];
    for (const a of view.args) {
      if (a.startsWith('-') || a === '!' || a === '(') break;
      roots.push(a);
    }
    if (!roots.length) roots.push('.');
    for (const r of roots) {
      const c = classifyDeleteTarget(r, r, ctx);
      if (c.kind === 'catastrophic') return finding('fs.find-delete', 'deny', `\`${view.name}\` with delete starting at \`${r}\` can wipe ${c.abs}.`);
      if (c.kind === 'outside' || c.kind === 'unresolved') return finding('fs.find-delete', 'ask', `\`${view.name}\` with delete outside the project (\`${r}\`).`);
    }
    return null;
  },
};

const DISK_DEVICE_RE = /^\/dev\/(sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d|rdisk\d|md\d|dm-\d|mapper\/)/;

const diskRule = {
  id: 'disk.destroy',
  description: 'Formatting, partitioning or overwriting a disk device (mkfs, dd of=/dev/…, diskutil erase…, wipefs, fdisk)',
  check(view) {
    const n = view.name;
    if (/^mkfs(\..+)?$/.test(n) || /^newfs(_.+)?$/.test(n) || n === 'wipefs' || n === 'mkswap') {
      return finding('disk.destroy', 'deny', `\`${n}\` formats a disk or partition.`);
    }
    if (['fdisk', 'sfdisk', 'gdisk', 'sgdisk', 'cfdisk'].includes(n) && view.args.some((a) => DISK_DEVICE_RE.test(a))) {
      return finding('disk.destroy', 'deny', `\`${n}\` rewrites a partition table.`);
    }
    if (n === 'parted' && view.args.some((a) => /^(mklabel|mkpart|rm|resizepart)$/.test(a))) {
      return finding('disk.destroy', 'deny', '`parted` is modifying a partition table.');
    }
    if (n === 'diskutil' && /^(eraseDisk|eraseVolume|partitionDisk|zeroDisk|randomDisk|secureErase|reformat|apfs)$/.test(view.args[0] ?? '')) {
      if (view.args[0] === 'apfs' && !/^(deleteContainer|deleteVolume|eraseVolume)$/.test(view.args[1] ?? '')) return null;
      return finding('disk.destroy', 'deny', `\`diskutil ${view.args[0]}\` erases data on a disk.`);
    }
    if (n === 'dd' && view.args.some((a) => a.startsWith('of=') && DISK_DEVICE_RE.test(a.slice(3)))) {
      return finding('disk.destroy', 'deny', '`dd` is writing directly to a disk device.');
    }
    if ((n === 'shred' || n === 'srm') && view.args.some((a) => DISK_DEVICE_RE.test(a))) {
      return finding('disk.destroy', 'deny', `\`${n}\` is overwriting a disk device.`);
    }
    for (const r of view.redirects) {
      if (/^(>|>>|>\||&>|&>>)$/.test(r.op) && DISK_DEVICE_RE.test(r.target)) {
        return finding('disk.destroy', 'deny', `Redirecting output into \`${r.target}\` overwrites a disk device.`);
      }
    }
    return null;
  },
};

const chmodRule = {
  id: 'fs.permissions',
  description: 'Recursive chmod/chown on /, $HOME or system folders (deny); recursive world-writable chmod (ask)',
  check(view, ctx) {
    if (!['chmod', 'chown', 'chgrp', 'chflags'].includes(view.name)) return null;
    const flags = flagSet(view.args);
    if (!flags.has('R', '--recursive')) return null;
    const pos = positionals(view.args);
    const targets = pos.slice(1);
    for (const t of targets) {
      const c = classifyDeleteTarget(t, t, ctx);
      if (c.kind === 'catastrophic') return finding('fs.permissions', 'deny', `Recursive \`${view.name}\` on \`${t}\` can break the system or lock you out.`);
    }
    if (view.name === 'chmod' && /^(0?777|a\+rwx|ugo\+rwx|o\+w|a\+w)$/.test(pos[0] ?? '')) {
      return finding('fs.permissions', 'ask', `Recursive \`chmod ${pos[0]}\` makes files world-writable.`);
    }
    return null;
  },
};

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

const powerRule = {
  id: 'sys.power',
  description: 'Shutdown / reboot / killing every process',
  check(view) {
    const n = view.name;
    if (['shutdown', 'reboot', 'halt', 'poweroff'].includes(n)) return finding('sys.power', 'ask', `\`${n}\` stops the machine.`);
    if (n === 'init' && /^[06]$/.test(view.args[0] ?? '')) return finding('sys.power', 'ask', '`init 0/6` stops the machine.');
    if (n === 'systemctl' && /^(poweroff|reboot|halt|kexec|suspend|hibernate)$/.test(sub(view) ?? '')) return finding('sys.power', 'ask', `\`systemctl ${sub(view)}\` stops the machine.`);
    if (n === 'kill' && view.args.includes('-1') && view.args.length >= 1 && view.args[view.args.length - 1] === '-1') return finding('sys.power', 'ask', '`kill … -1` signals every process you own.');
    if (n === 'kill' && view.args.some((a, i) => a === '-1' && i > 0 && /^-(9|KILL|SIGKILL|TERM|15)$/.test(view.args[i - 1]))) return finding('sys.power', 'ask', '`kill -9 -1` kills every process you own.');
    return null;
  },
};

const persistenceRule = {
  id: 'sys.persistence',
  description: 'Changing cron jobs, launch agents or system services',
  check(view) {
    const n = view.name;
    if (n === 'crontab') {
      if (view.args.includes('-l')) return null;
      if (view.args.includes('-r')) return finding('sys.persistence', 'ask', '`crontab -r` deletes all your cron jobs.');
      return finding('sys.persistence', 'ask', '`crontab` installs or edits scheduled jobs.');
    }
    if (n === 'launchctl' && /^(load|unload|bootstrap|bootout|remove|enable|disable|submit)$/.test(view.args[0] ?? '')) {
      return finding('sys.persistence', 'ask', `\`launchctl ${view.args[0]}\` changes background services.`);
    }
    if (n === 'systemctl' && /^(enable|disable|mask|stop|kill|daemon-reload|link)$/.test(sub(view) ?? '')) {
      return finding('sys.persistence', 'ask', `\`systemctl ${sub(view)}\` changes system services.`);
    }
    return null;
  },
};

// ---------------------------------------------------------------------------
// Remote code execution
// ---------------------------------------------------------------------------

const DOWNLOADERS = new Set(['curl', 'wget', 'fetch', 'http', 'https', 'xh', 'aria2c', 'iwr', 'invoke-webrequest', 'irm']);
const INTERPRETERS = new Set(['python', 'python3', 'python2', 'node', 'deno', 'bun', 'perl', 'ruby', 'php', 'pwsh', 'powershell', 'osascript', 'lua']);

function isExecutor(view) {
  return isShell(view.name) || INTERPRETERS.has(view.name) || view.name === 'source' || view.name === '.';
}

function isDecoder(view) {
  if (view.name === 'base64' || view.name === 'gbase64') return view.args.some((a) => a === '-d' || a === '-D' || a === '--decode');
  if (view.name === 'xxd') return view.args.includes('-r');
  if (view.name === 'openssl') return view.args.includes('base64') && view.args.includes('-d');
  if (view.name === 'uudecode' || view.name === 'rev') return true;
  return false;
}

const pipeToShellRule = {
  id: 'exec.pipe-to-shell',
  description: 'Piping downloaded content into a shell/interpreter (ask) or decoded/obfuscated content into a shell (deny)',
  check(view) {
    if (view.pipeIndex === 0 || !isExecutor(view)) return null;
    // `bash` reading a script file argument is not stdin execution
    const pos = positionals(view.args);
    if (pos.length && !['-', '/dev/stdin'].includes(pos[0])) return null;
    const upstream = view.pipeline.slice(0, view.pipeIndex);
    if (upstream.some(isDecoder)) {
      return finding('exec.pipe-to-shell', 'deny', 'Decoded/obfuscated content is being piped into a shell. This hides what will actually run.');
    }
    const dl = upstream.find((u) => DOWNLOADERS.has(u.name));
    if (dl) {
      const url = positionals(dl.args).find((a) => /^https?:\/\//.test(a)) ?? 'a remote URL';
      return finding('exec.pipe-to-shell', 'ask', `Remote code from ${url} is piped straight into \`${view.name}\` without review.`);
    }
    return null;
  },
};

const procSubRule = {
  id: 'exec.pipe-to-shell',
  description: null,
  check(view) {
    if (!isExecutor(view)) return null;
    const ps = view.words.find((w) => w.procSub && /^\s*(curl|wget)\b/.test(w.procSub));
    if (ps) return finding('exec.pipe-to-shell', 'ask', `Remote code is executed via process substitution \`${ps.raw}\` without review.`);
    return null;
  },
};

// ---------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------

function gitSub(view) {
  // Skip global options: git -C dir, -c k=v, --git-dir=…, --no-pager, etc.
  const a = view.args;
  let i = 0;
  while (i < a.length && a[i].startsWith('-')) {
    if (a[i] === '-C' || a[i] === '-c' || a[i] === '--git-dir' || a[i] === '--work-tree' || a[i] === '--namespace') i += 2;
    else i++;
  }
  return { sub: a[i], rest: a.slice(i + 1) };
}

function branchMatches(branch, patterns) {
  return matchesAnyGlob(branch, patterns) || patterns.includes(branch);
}

function parsePushRefspecs(rest) {
  const pos = positionals(rest.filter((a, i) => !(['-o', '--push-option', '--repo', '--receive-pack', '--exec'].includes(rest[i - 1]))));
  // pos[0] is the remote (if any), the rest are refspecs
  const refspecs = pos.slice(1);
  return refspecs.map((spec) => {
    const forced = spec.startsWith('+');
    const s = forced ? spec.slice(1) : spec;
    const deleting = s.startsWith(':');
    const dst = s.includes(':') ? s.split(':').pop() : s;
    return { forced, deleting, dst: dst.replace(/^refs\/heads\//, '') };
  });
}

const gitRules = [
  {
    id: 'git.force-push',
    description: 'Force push to a protected branch (deny) or any other branch (ask); --mirror (ask)',
    check(view, ctx) {
      if (view.name !== 'git') return null;
      const { sub: s, rest } = gitSub(view);
      if (s !== 'push') return null;
      const flags = flagSet(rest);
      const refspecs = parsePushRefspecs(rest);
      const forced = flags.has('f', '--force') || flags.long.has('--force-with-lease') || flags.long.has('--force-if-includes') || refspecs.some((r) => r.forced);
      const mirror = flags.long.has('--mirror');
      if (mirror) return finding('git.force-push', 'ask', '`git push --mirror` overwrites every ref on the remote.');
      if (!forced) return null;
      const protectedBranches = ctx.config.protectedBranches;
      const hit = refspecs.find((r) => branchMatches(r.dst, protectedBranches));
      if (hit) return finding('git.force-push', 'deny', `Force push to protected branch \`${hit.dst}\` rewrites shared history.`);
      if (flags.long.has('--all')) return finding('git.force-push', 'deny', 'Force push with `--all` rewrites every branch, including protected ones.');
      const target = refspecs.length ? refspecs.map((r) => r.dst).join(', ') : 'the current branch (unknown name)';
      return finding('git.force-push', 'ask', `Force push to ${target} rewrites remote history.`);
    },
  },
  {
    id: 'git.push-delete',
    description: 'Deleting remote branches/tags via push',
    check(view, ctx) {
      if (view.name !== 'git') return null;
      const { sub: s, rest } = gitSub(view);
      if (s !== 'push') return null;
      const flags = flagSet(rest);
      const refspecs = parsePushRefspecs(rest);
      const deleting = flags.has('d', '--delete') ? refspecs : refspecs.filter((r) => r.deleting);
      if (!deleting.length) return null;
      const prot = deleting.find((r) => branchMatches(r.dst, ctx.config.protectedBranches));
      if (prot) return finding('git.push-delete', 'deny', `Deleting protected remote branch \`${prot.dst}\`.`);
      return finding('git.push-delete', 'ask', `Deleting remote ref(s): ${deleting.map((r) => `\`${r.dst}\``).join(', ')}.`);
    },
  },
  {
    id: 'git.discard-work',
    description: 'Commands that throw away uncommitted or unpushed work (reset --hard, clean -fdx, checkout ., restore ., stash clear/drop, branch -D)',
    check(view) {
      if (view.name !== 'git') return null;
      const { sub: s, rest } = gitSub(view);
      const flags = flagSet(rest);
      const pos = positionals(rest);
      switch (s) {
        case 'reset':
          if (flags.long.has('--hard')) return finding('git.discard-work', 'ask', '`git reset --hard` discards all uncommitted changes.');
          return null;
        case 'clean':
          if (flags.has('n', '--dry-run')) return null;
          if (flags.has('f', '--force') && (flags.has('d') || flags.has('x') || flags.has('X'))) return finding('git.discard-work', 'ask', `\`git clean ${rest.filter((a) => a.startsWith('-')).join(' ')}\` permanently deletes untracked${flags.has('x') ? ' and ignored' : ''} files.`);
          return null;
        case 'checkout':
          if (rest.includes('--') && pos.some((p) => p === '.' || p === ':/')) return finding('git.discard-work', 'ask', '`git checkout -- .` discards all uncommitted changes.');
          if (pos.length === 1 && (pos[0] === '.' || pos[0] === ':/')) return finding('git.discard-work', 'ask', '`git checkout .` discards all uncommitted changes.');
          if (flags.has('f', '--force')) return finding('git.discard-work', 'ask', '`git checkout --force` discards local changes.');
          return null;
        case 'restore':
          if (flags.has('S', '--staged') && !flags.has('W', '--worktree')) return null;
          if (pos.some((p) => p === '.' || p === ':/')) return finding('git.discard-work', 'ask', '`git restore .` discards all uncommitted changes.');
          return null;
        case 'stash':
          if (pos[0] === 'clear') return finding('git.discard-work', 'ask', '`git stash clear` permanently deletes all stashes.');
          if (pos[0] === 'drop') return finding('git.discard-work', 'ask', '`git stash drop` permanently deletes a stash.');
          return null;
        case 'branch':
          if (flags.has('D') || (flags.has('d', '--delete') && flags.has('f', '--force'))) return finding('git.discard-work', 'ask', `\`git branch -D\` deletes ${pos.join(', ') || 'a branch'} even if it is not merged.`);
          return null;
        default:
          return null;
      }
    },
  },
  {
    id: 'git.history-rewrite',
    description: 'History rewriting / garbage collection that makes recovery impossible (filter-branch, filter-repo, reflog expire, gc --prune=now, update-ref -d)',
    check(view) {
      if (view.name !== 'git' && view.name !== 'git-filter-repo' && view.name !== 'bfg') return null;
      if (view.name !== 'git') return finding('git.history-rewrite', 'ask', `\`${view.name}\` rewrites repository history.`);
      const { sub: s, rest } = gitSub(view);
      if (s === 'filter-branch' || s === 'filter-repo') return finding('git.history-rewrite', 'ask', `\`git ${s}\` rewrites repository history.`);
      if (s === 'reflog' && rest[0] === 'expire') return finding('git.history-rewrite', 'ask', '`git reflog expire` removes the safety net for recovering lost commits.');
      if (s === 'gc' && rest.some((a) => /^--prune=(now|all)$/.test(a))) return finding('git.history-rewrite', 'ask', '`git gc --prune=now` permanently deletes unreachable commits.');
      if (s === 'update-ref' && rest.includes('-d')) return finding('git.history-rewrite', 'ask', '`git update-ref -d` deletes a ref directly.');
      return null;
    },
  },
  {
    id: 'git.skip-hooks',
    description: 'Bypassing git hooks (--no-verify, core.hooksPath changes)',
    check(view) {
      if (view.name !== 'git') return null;
      const { sub: s, rest } = gitSub(view);
      const flags = flagSet(rest);
      if (['commit', 'push', 'merge', 'am', 'rebase', 'cherry-pick', 'revert'].includes(s) && (flags.long.has('--no-verify') || (s === 'commit' && flags.short.has('n')))) {
        return finding('git.skip-hooks', 'ask', `\`git ${s} --no-verify\` skips the repository's pre-commit/pre-push checks.`);
      }
      if (s === 'config' && rest.some((a) => /^core\.hookspath$/i.test(a)) && !rest.includes('--get')) {
        return finding('git.skip-hooks', 'ask', 'Changing `core.hooksPath` can silently disable repository hooks.');
      }
      const cfg = view.args.findIndex((a, i) => view.args[i - 1] === '-c' && /^core\.hookspath=/i.test(a));
      if (cfg !== -1) return finding('git.skip-hooks', 'ask', 'Overriding `core.hooksPath` on the command line disables repository hooks.');
      return null;
    },
  },
  {
    id: 'git.add-secrets',
    description: 'Staging credential files (.env, keys) or force-adding ignored files',
    check(view) {
      if (view.name !== 'git') return null;
      const { sub: s, rest } = gitSub(view);
      if (s !== 'add' && s !== 'stage') return null;
      const flags = flagSet(rest);
      const files = positionals(rest);
      const secret = files.find((f) => isSecretFile(f));
      if (secret) return finding('git.add-secrets', 'ask', `\`${secret}\` looks like a credentials file; committing it leaks secrets into git history.`);
      if (flags.has('f', '--force')) return finding('git.add-secrets', 'ask', '`git add --force` stages files that .gitignore deliberately excludes.');
      return null;
    },
  },
];

// ---------------------------------------------------------------------------
// GitHub CLI
// ---------------------------------------------------------------------------

const ghRule = {
  id: 'gh.destructive',
  description: 'Deleting repositories/releases or changing repository visibility with the GitHub CLI',
  check(view) {
    if (view.name !== 'gh') return null;
    const [a0, a1] = positionals(view.args);
    if (a0 === 'repo' && a1 === 'delete') return finding('gh.destructive', 'deny', '`gh repo delete` permanently deletes a GitHub repository.');
    if (a0 === 'repo' && (a1 === 'archive' || a1 === 'rename')) return finding('gh.destructive', 'ask', `\`gh repo ${a1}\` changes the repository for everyone.`);
    if (a0 === 'repo' && a1 === 'edit' && view.args.some((a) => a.startsWith('--visibility'))) return finding('gh.destructive', 'ask', 'Changing repository visibility can expose private code.');
    if (a0 === 'release' && a1 === 'delete') return finding('gh.destructive', 'ask', '`gh release delete` removes a published release.');
    if (a0 === 'secret' && a1 === 'delete') return finding('gh.destructive', 'ask', '`gh secret delete` removes a repository secret.');
    if (a0 === 'api' && view.args.some((a, i) => (a === '-X' || a === '--method') && /^DELETE$/i.test(view.args[i + 1] ?? ''))) return finding('gh.destructive', 'ask', '`gh api -X DELETE` performs a destructive API call.');
    return null;
  },
};

// ---------------------------------------------------------------------------
// Databases
// ---------------------------------------------------------------------------

const DB_CLIENTS = new Set(['psql', 'mysql', 'mariadb', 'sqlite3', 'sqlite', 'sqlcmd', 'mongosh', 'mongo', 'clickhouse-client', 'clickhouse', 'cockroach', 'duckdb', 'pgcli', 'mycli', 'litecli', 'usql', 'turso', 'wrangler', 'bq', 'snowsql', 'redis-cli', 'cqlsh']);

const DESTRUCTIVE_SQL_RE = /\b(?:DROP\s+(?:DATABASE|SCHEMA|TABLE|COLLECTION|KEYSPACE|INDEX)|TRUNCATE\s+(?:TABLE\s+)?[\w."`[]|DELETE\s+FROM\s+[\w."`[\]]+\s*(?:;|$)|ALTER\s+TABLE\s+[\w."`[\]]+\s+DROP\s+COLUMN)|\.dropDatabase\s*\(|\.drop\s*\(\s*\)|\bdeleteMany\s*\(\s*\{\s*\}\s*\)|\bFLUSHALL\b|\bFLUSHDB\b/i;

const dbSqlRule = {
  id: 'db.destructive-sql',
  description: 'DROP / TRUNCATE / DELETE without WHERE / FLUSHALL via a database client (ask; deny when the command mentions production)',
  check(view) {
    const body = [view.args.join(' '), ...view.heredocBodies].join('\n');
    if (!DB_CLIENTS.has(view.name) && !(view.name === 'npx' && /prisma/.test(view.args[0] ?? ''))) return null;
    if (view.name === 'wrangler' && !(view.args[0] === 'd1' && view.args[1] === 'execute')) return null;
    if (view.name === 'bq' && view.args[0] === 'rm') return finding('db.destructive-sql', escalateOnProd(view, 'ask'), '`bq rm` deletes BigQuery datasets/tables.');
    if (!DESTRUCTIVE_SQL_RE.test(body)) return null;
    const what = (body.match(DESTRUCTIVE_SQL_RE) || [''])[0].trim().replace(/\s+/g, ' ');
    return finding('db.destructive-sql', escalateOnProd(view, 'ask'), `Destructive database statement \`${what}\`${mentionsProduction(view) ? ' against what looks like PRODUCTION' : ''}.`);
  },
};

const dbToolRule = {
  id: 'db.reset',
  description: 'ORM/framework commands that drop or reset a database (prisma migrate reset, db push --accept-data-loss, rails db:drop, artisan migrate:fresh, manage.py flush, dropdb, supabase db reset …)',
  check(view) {
    const args = view.args;
    const joined = args.join(' ');
    let hit = null;
    const n = view.name;
    const isPrisma = n === 'prisma' || ((n === 'npx' || n === 'pnpx' || n === 'bunx' || (n === 'pnpm' && args[0] === 'exec') || (n === 'yarn' && args[0] !== 'run')) && /\bprisma\b/.test(joined));
    if (isPrisma) {
      if (/\bmigrate\s+reset\b/.test(joined)) hit = 'prisma migrate reset';
      else if (/\bdb\s+push\b/.test(joined) && /--(force-reset|accept-data-loss)\b/.test(joined)) hit = 'prisma db push --force-reset/--accept-data-loss';
    }
    if (n === 'drizzle-kit' || /drizzle-kit/.test(joined)) {
      if (/\b(drop|push\b.*--force)/.test(joined)) hit = 'drizzle-kit drop/force push';
    }
    if ((n === 'rails' || n === 'rake' || (n === 'bin/rails')) && args.some((a) => /^db:(drop|reset|purge|schema:load|truncate_all)$/.test(a))) hit = `rails ${args.find((a) => a.startsWith('db:'))}`;
    if ((n === 'php' && args[0] === 'artisan') && /^(migrate:fresh|migrate:reset|db:wipe|migrate:refresh)$/.test(args[1] ?? '')) hit = `artisan ${args[1]}`;
    if (/^python[0-9.]*$/.test(n) && /manage\.py$/.test(args[0] ?? '') && /^(flush|reset_db|sqlflush)$/.test(args[1] ?? '')) hit = `manage.py ${args[1]}`;
    if (n === 'dropdb' || n === 'dropuser') hit = n;
    if (n === 'supabase' && /\bdb\s+reset\b/.test(joined) && !/--local/.test(joined)) hit = 'supabase db reset';
    if (n === 'supabase' && /\bdb\s+reset\b/.test(joined) && /--linked/.test(joined)) hit = 'supabase db reset --linked';
    if ((n === 'sequelize' || /sequelize-cli/.test(joined)) && /\bdb:drop\b|db:migrate:undo:all/.test(joined)) hit = 'sequelize db:drop';
    if (n === 'knex' && /migrate:rollback\b.*--all/.test(joined)) hit = 'knex migrate:rollback --all';
    if (n === 'typeorm' && /schema:drop/.test(joined)) hit = 'typeorm schema:drop';
    if (n === 'firebase' && /firestore:delete\b/.test(joined) && /--all-collections|-r\b|--recursive/.test(joined)) hit = 'firebase firestore:delete';
    if (!hit) return null;
    return finding('db.reset', escalateOnProd(view, 'ask'), `\`${hit}\` wipes database data${mentionsProduction(view) ? ' and the command mentions PRODUCTION' : ''}.`);
  },
};

// ---------------------------------------------------------------------------
// Cloud / infrastructure
// ---------------------------------------------------------------------------

const infraRule = {
  id: 'infra.destroy',
  description: 'Destroying cloud/infra resources (terraform destroy, kubectl delete, helm uninstall, aws … delete/terminate, gcloud/az delete, docker volume prune …)',
  check(view) {
    const n = view.name;
    const a = view.args;
    const pos = positionals(a);
    const joined = a.join(' ');
    const ask = (what) => finding('infra.destroy', escalateOnProd(view, 'ask'), `\`${what}\` destroys infrastructure or data${mentionsProduction(view) ? ' and the command mentions PRODUCTION' : ''}.`);

    if (['terraform', 'tofu', 'terragrunt'].includes(n)) {
      if (pos[0] === 'destroy' || (pos[0] === 'apply' && a.includes('-destroy'))) return ask(`${n} destroy`);
      if (pos[0] === 'apply' && a.some((x) => x === '-auto-approve' || x === '--auto-approve')) return ask(`${n} apply -auto-approve`);
      if (pos[0] === 'state' && pos[1] === 'rm') return ask(`${n} state rm`);
      if (pos[0] === 'workspace' && pos[1] === 'delete') return ask(`${n} workspace delete`);
    }
    if (n === 'pulumi' && (pos[0] === 'destroy' || (pos[0] === 'stack' && pos[1] === 'rm'))) return ask(`pulumi ${pos.slice(0, 2).join(' ')}`);
    if ((n === 'kubectl' || n === 'oc' || n === 'k') && ['delete', 'drain', 'replace'].includes(pos[0])) {
      if (pos[0] === 'replace' && !a.includes('--force')) return null;
      return ask(`${n} ${pos.slice(0, 3).join(' ')}`);
    }
    if (n === 'helm' && ['uninstall', 'delete', 'del', 'un'].includes(pos[0])) return ask(`helm ${pos[0]}`);
    if (n === 'aws') {
      const svc = pos[0];
      const op = pos[1] ?? '';
      if (svc === 's3' && (op === 'rb' || (op === 'rm' && a.includes('--recursive')))) return ask(`aws s3 ${op}`);
      if (svc === 's3api' && /^delete-/.test(op)) return ask(`aws s3api ${op}`);
      if (/^(delete-|terminate-|remove-|deregister-|purge-|destroy-)/.test(op)) return ask(`aws ${svc} ${op}`);
    }
    if ((n === 'gcloud' || n === 'gsutil') && (pos.includes('delete') || (n === 'gsutil' && (pos[0] === 'rm' && a.includes('-r') || pos[0] === 'rb')))) return ask(`${n} ${pos.slice(0, 3).join(' ')}`);
    if (n === 'az' && pos.includes('delete')) return ask(`az ${pos.slice(0, 3).join(' ')}`);
    if (n === 'doctl' && pos.some((p) => p === 'delete' || p === 'rm')) return ask(`doctl ${pos.slice(0, 3).join(' ')}`);
    if ((n === 'fly' || n === 'flyctl') && (pos.includes('destroy') || (pos[0] === 'volumes' && ['destroy', 'delete'].includes(pos[1])))) return ask(`${n} ${pos.slice(0, 2).join(' ')}`);
    if (n === 'heroku' && /^(apps:destroy|pg:reset|apps:delete|addons:destroy)$/.test(pos[0] ?? '')) return ask(`heroku ${pos[0]}`);
    if (n === 'vercel' && ['remove', 'rm'].includes(pos[0])) return ask(`vercel ${pos[0]}`);
    if (n === 'netlify' && pos[0] === 'sites:delete') return ask('netlify sites:delete');
    if (n === 'railway' && pos[0] === 'down') return ask('railway down');
    if (n === 'supabase' && pos[0] === 'projects' && pos[1] === 'delete') return ask('supabase projects delete');
    if (n === 'docker' || n === 'podman') {
      if (pos[0] === 'system' && pos[1] === 'prune') return ask(`${n} system prune`);
      if (pos[0] === 'volume' && ['prune', 'rm'].includes(pos[1])) return ask(`${n} volume ${pos[1]}`);
      if ((pos[0] === 'compose' && pos.includes('down')) && (a.includes('-v') || a.includes('--volumes'))) return ask(`${n} compose down -v`);
    }
    if ((n === 'docker-compose') && pos.includes('down') && (a.includes('-v') || a.includes('--volumes'))) return ask('docker-compose down -v');
    if (n === 'wrangler' && ['delete'].includes(pos[0])) return ask('wrangler delete');
    if (n === 'wrangler' && ['d1', 'kv', 'r2', 'queues'].includes(pos[0]) && /delete/.test(joined)) return ask(`wrangler ${pos.slice(0, 3).join(' ')}`);
    return null;
  },
};

// ---------------------------------------------------------------------------
// Publishing and deploying
// ---------------------------------------------------------------------------

const publishRule = {
  id: 'release.publish',
  description: 'Publishing packages/images to public registries (npm/pnpm/yarn publish, cargo publish, twine upload, docker push …)',
  check(view) {
    const n = view.name;
    const pos = positionals(view.args);
    const dry = view.args.some((a) => a === '--dry-run' || a === '-n' && n === 'cargo');
    if (dry) return null;
    const pub = (what) => finding('release.publish', 'ask', `\`${what}\` publishes to a public registry; it usually cannot be undone.`);
    if (['npm', 'pnpm', 'yarn', 'bun'].includes(n) && (pos[0] === 'publish' || (n === 'yarn' && pos[0] === 'npm' && pos[1] === 'publish'))) return pub(`${n} publish`);
    if (n === 'npm' && pos[0] === 'unpublish') return finding('release.publish', 'ask', '`npm unpublish` removes a published package version.');
    if (n === 'npm' && pos[0] === 'deprecate') return pub('npm deprecate');
    if (n === 'cargo' && pos[0] === 'publish') return pub('cargo publish');
    if (n === 'twine' && pos[0] === 'upload') return pub('twine upload');
    if ((n === 'poetry' || n === 'uv' || n === 'hatch' || n === 'flit' || n === 'pdm') && pos[0] === 'publish') return pub(`${n} publish`);
    if (n === 'gem' && pos[0] === 'push') return pub('gem push');
    if ((n === 'docker' || n === 'podman') && (pos[0] === 'push' || (pos[0] === 'image' && pos[1] === 'push') || (pos[0] === 'buildx' && view.args.includes('--push')))) return pub(`${n} push`);
    if (n === 'dotnet' && pos[0] === 'nuget' && pos[1] === 'push') return pub('dotnet nuget push');
    if ((n === 'mvn' || n === 'mvnw' || n === './mvnw') && pos.includes('deploy')) return pub('mvn deploy');
    if ((n === 'gradle' || n === 'gradlew' || n === './gradlew') && pos.some((p) => /^publish/.test(p))) return pub('gradle publish');
    if ((n === 'flutter' || n === 'dart') && pos[0] === 'pub' && pos[1] === 'publish') return pub(`${n} pub publish`);
    if ((n === 'vsce' || n === 'ovsx') && pos[0] === 'publish') return pub(`${n} publish`);
    if (n === 'gh' && pos[0] === 'release' && pos[1] === 'create') return null;
    return null;
  },
};

const deployRule = {
  id: 'release.deploy-production',
  description: 'Deploying to production (vercel --prod, netlify deploy --prod, firebase deploy, fly deploy, wrangler deploy, eas submit, fastlane deliver …)',
  check(view) {
    const n = view.name;
    const a = view.args;
    const pos = positionals(a);
    const prod = (what) => finding('release.deploy-production', 'ask', `\`${what}\` deploys to a live environment.`);
    if (n === 'vercel' && (a.includes('--prod') || a.includes('--production') || pos[0] === 'promote')) return prod('vercel --prod');
    if (n === 'netlify' && pos[0] === 'deploy' && (a.includes('--prod') || a.includes('-p'))) return prod('netlify deploy --prod');
    if (n === 'firebase' && pos[0] === 'deploy') return prod('firebase deploy');
    if ((n === 'fly' || n === 'flyctl') && pos[0] === 'deploy') return prod(`${n} deploy`);
    if (n === 'wrangler' && (pos[0] === 'deploy' || pos[0] === 'publish')) return prod(`wrangler ${pos[0]}`);
    if (n === 'railway' && pos[0] === 'up') return prod('railway up');
    if ((n === 'serverless' || n === 'sls') && pos[0] === 'deploy' && mentionsProduction(view)) return prod(`${n} deploy (prod stage)`);
    if (n === 'eas' && pos[0] === 'submit') return prod('eas submit');
    if (n === 'fastlane' && /^(deliver|supply|release|upload_to_app_store|upload_to_play_store|pilot)$/.test(pos[0] ?? pos[1] ?? '')) return prod(`fastlane ${pos[0]}`);
    if (n === 'git' && pos[0] === 'push' && /^heroku$/.test(pos[1] ?? '')) return prod('git push heroku');
    if (n === 'kubectl' && pos[0] === 'apply' && mentionsProduction(view)) return prod('kubectl apply (production)');
    if (n === 'helm' && ['install', 'upgrade'].includes(pos[0]) && mentionsProduction(view)) return prod(`helm ${pos[0]} (production)`);
    return null;
  },
};

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

const READERS = new Set(['cat', 'less', 'more', 'head', 'tail', 'bat', 'batcat', 'nl', 'tac', 'strings', 'xxd', 'od', 'hexdump', 'base64', 'gbase64', 'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'sed', 'awk', 'gawk', 'jq', 'yq', 'cut', 'sort', 'uniq', 'view', 'vim', 'vi', 'nano', 'emacs', 'code', 'open', 'pbcopy', 'dotenv', 'source', '.']);
const NETWORK = new Set(['curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'telnet', 'scp', 'sftp', 'ftp', 'rsync', 'http', 'https', 'xh', 'aws', 'gsutil', 'rclone', 'sendmail', 'mail', 'mutt', 'ssh']);

function secretFileArgs(view) {
  return view.args
    .flatMap((a) => {
      // curl -d @file, -F x=@file, --upload-file file, rsync src host:
      const m = a.match(/@([^;,\s]+)/);
      return m ? [a, m[1]] : [a];
    })
    .filter((a) => !a.startsWith('-') && isSecretFile(a.replace(/^[^=]+=/, '')));
}

const secretReadRule = {
  id: 'secrets.read',
  description: 'Reading credential files (.env, private keys, cloud credentials) via the Read tool or shell (cat, grep, …)',
  check(view) {
    if (!READERS.has(view.name)) return null;
    if (view.name === 'source' || view.name === '.' || view.name === 'dotenv') return null; // loads env without printing
    const hit = positionals(view.args).find((a) => isSecretFile(a));
    if (!hit) return null;
    return finding('secrets.read', 'ask', `\`${view.name} ${hit}\` prints a credentials file into the conversation/transcript.`);
  },
};

const secretExfilRule = {
  id: 'secrets.exfiltrate',
  description: 'Sending credential files or environment dumps over the network',
  check(view) {
    if (!NETWORK.has(view.name)) return null;
    const direct = secretFileArgs(view);
    if (direct.length) return finding('secrets.exfiltrate', 'deny', `\`${view.name}\` is sending a credentials file (\`${direct[0]}\`) over the network.`);
    if (view.pipeIndex > 0) {
      const upstream = view.pipeline.slice(0, view.pipeIndex);
      const src = upstream.find((u) => (READERS.has(u.name) && positionals(u.args).some((a) => isSecretFile(a))) || ['env', 'printenv', 'set', 'export'].includes(u.name) && positionals(u.args).length === 0);
      if (src) return finding('secrets.exfiltrate', 'deny', `Secrets from \`${src.name}${src.args.length ? ' ' + src.args.join(' ') : ''}\` are piped into \`${view.name}\`, which sends data over the network.`);
    }
    return null;
  },
};

const SECRET_VAR_RE = /\$\{?([A-Za-z_][A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|CREDENTIALS?|PRIVATE)[A-Za-z0-9_]*)\}?/i;

const envDumpRule = {
  id: 'secrets.env-dump',
  description: 'Dumping all environment variables or echoing secret-named variables',
  check(view) {
    const n = view.name;
    const pos = positionals(view.args);
    if ((n === 'env' || n === 'printenv') && pos.length === 0) return finding('secrets.env-dump', 'ask', `\`${n}\` prints every environment variable, including API keys, into the transcript.`);
    if ((n === 'export' && (view.args.includes('-p') || view.args.length === 0)) || (n === 'set' && view.args.length === 0) || (n === 'declare' && view.args.includes('-x') && pos.length === 0)) {
      return finding('secrets.env-dump', 'ask', `\`${n}\` prints environment variables, including API keys, into the transcript.`);
    }
    if (n === 'printenv' && pos.some((p) => SECRET_VAR_RE.test(`$${p}`))) return finding('secrets.env-dump', 'ask', `\`printenv ${pos.join(' ')}\` prints a secret value into the transcript.`);
    if ((n === 'echo' || n === 'printf') && view.pipeIndex === 0) {
      const m = view.args.join(' ').match(SECRET_VAR_RE);
      if (m && !/:\+|:-?\*/.test(m[0]) && !view.redirects.some((r) => /^(>|>>)$/.test(r.op))) {
        return finding('secrets.env-dump', 'ask', `Echoing \`$${m[1]}\` prints a secret value into the transcript. Check it with \`[ -n "$${m[1]}" ]\` instead.`);
      }
    }
    return null;
  },
};

// ---------------------------------------------------------------------------
// Writes to protected files (via redirects, tee, cp, mv, sed -i, rm …)
// ---------------------------------------------------------------------------

function writeTargets(view) {
  const out = [];
  for (const r of view.redirects) {
    if (/^(>|>>|>\||&>|&>>|<>)$/.test(r.op) && r.target && r.fd !== '0' && !/^\/dev\/(null|stdout|stderr|tty)$/.test(r.target) && !/^&?\d$/.test(r.target)) {
      out.push({ path: r.target, via: `${r.op} redirect` });
    }
  }
  const n = view.name;
  const pos = positionals(view.args);
  if (n === 'tee') pos.forEach((p) => out.push({ path: p, via: 'tee' }));
  if (['cp', 'install', 'ln', 'rsync'].includes(n) && pos.length >= 2) out.push({ path: pos[pos.length - 1], via: n });
  if (n === 'mv' && pos.length >= 2) pos.forEach((p) => out.push({ path: p, via: 'mv' }));
  if (['rm', 'unlink', 'truncate', 'shred'].includes(n)) pos.forEach((p) => out.push({ path: p, via: n }));
  if ((n === 'sed' || n === 'gsed') && view.args.some((a) => a === '-i' || a.startsWith('-i') || a === '--in-place' || a.startsWith('--in-place='))) {
    const exprs = view.args.filter((a) => a === '-e' || a === '--expression' || a === '-f' || a === '--file').length;
    pos.slice(exprs ? exprs : 1).forEach((p) => out.push({ path: p, via: 'sed -i' }));
  }
  if (n === 'perl' && view.args.some((a) => /^-[a-zA-Z]*i/.test(a))) pos.slice(1).forEach((p) => out.push({ path: p, via: 'perl -i' }));
  if (n === 'dd') view.args.filter((a) => a.startsWith('of=')).forEach((a) => out.push({ path: a.slice(3), via: 'dd' }));
  if (n === 'chmod' || n === 'chown') pos.slice(1).forEach((p) => out.push({ path: p, via: n }));
  return out;
}

const SYSTEM_WRITE_RE = /^\/(bin|sbin|usr|System|boot|lib|lib64)(\/|$)/;

const protectedWriteRule = {
  id: 'fs.protected-write',
  description: "Changing the guard's own config, agent hook settings, shell startup files, ~/.ssh or /etc (ask); git internals or system binaries (deny) — via file tools or shell",
  check(view, ctx) {
    const out = [];
    for (const t of writeTargets(view)) {
      const e = expandPath(t.path, ctx);
      const p = e.abs ?? t.path;
      if (e.abs && SYSTEM_WRITE_RE.test(e.abs)) {
        if (t.via === 'rm') continue; // covered by fs.rm-recursive
        out.push(finding('fs.protected-write', 'deny', `Writing to system path \`${p}\` (${t.via}).`));
      } else if (isGuardConfigFile(p)) {
        out.push(finding('fs.protected-write', 'ask', `\`${t.via}\` modifies \`${t.path}\`, which configures the agent's own guard rails/hooks.`));
      } else if (isPersistenceFile(p)) {
        out.push(finding('fs.protected-write', 'ask', `\`${t.via}\` modifies \`${t.path}\` (shell startup, SSH access or system config).`));
      } else if (ctx.config.protectedPaths.length && matchesAnyGlob(isWithin(p, ctx.projectDir) ? p.slice(ctx.projectDir.length + 1) : p, ctx.config.protectedPaths)) {
        out.push(finding('fs.protected-write', 'ask', `\`${t.via}\` modifies protected path \`${t.path}\`.`));
      }
    }
    return out;
  },
};

// Exported for the engine: secrets written by the shell into non-env files.
export function shellWriteTargets(view) {
  return writeTargets(view).filter((t) => !isEnvFile(t.path));
}

export const BASH_RULES = [
  rmRule,
  findDeleteRule,
  diskRule,
  chmodRule,
  powerRule,
  persistenceRule,
  pipeToShellRule,
  procSubRule,
  ...gitRules,
  ghRule,
  dbSqlRule,
  dbToolRule,
  infraRule,
  publishRule,
  deployRule,
  secretReadRule,
  secretExfilRule,
  envDumpRule,
  protectedWriteRule,
];

export { basename };
