// A small, dependency-free POSIX-ish shell lexer.
//
// It is NOT a full shell implementation. Its job is to turn a command line into
// a list of simple commands (argv + redirects + env assignments) so that rules
// can reason about *what will run*, instead of regex-matching raw text.
//
// Handled: quoting ('', "", \), operators (; && || | |& & newline), subshell
// parens, comments, redirects (incl. fd prefixes, &>, >|), heredocs, command
// substitution $( ) and ` `, process substitution <( ) >( ), and leading
// NAME=value assignments. Nested command strings are returned separately so
// the caller can analyse them recursively.

const OPERATOR_SEPARATORS = new Set([';', '&&', '||', '|', '|&', '&', '\n', '(', ')', ';;']);
const SHELL_KEYWORDS = new Set([
  'if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', '!', '{', '}', 'time',
]);
const NON_EXEC_KEYWORDS = new Set(['for', 'case', 'esac', 'select', 'function', 'in']);

/**
 * Read a balanced `( ... )` region starting right after the opening paren.
 * Returns { inner, end } where end is the index of the closing paren.
 */
function readBalanced(src, start) {
  let depth = 1;
  let i = start;
  let quote = null;
  while (i < src.length) {
    const ch = src[i];
    if (quote) {
      if (ch === '\\' && quote === '"') { i += 2; continue; }
      if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (ch === '\\') { i += 2; continue; }
    if (ch === "'" || ch === '"') { quote = ch; i++; continue; }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return { inner: src.slice(start, i), end: i };
    }
    i++;
  }
  return { inner: src.slice(start), end: src.length };
}

function readBacktick(src, start) {
  let i = start;
  while (i < src.length) {
    if (src[i] === '\\') { i += 2; continue; }
    if (src[i] === '`') return { inner: src.slice(start, i), end: i };
    i++;
  }
  return { inner: src.slice(start), end: src.length };
}

/**
 * Tokenize into words and operators.
 * Word token: { type: 'word', value, raw, quoted }
 * Op token:   { type: 'op', value }
 * Redirect:   { type: 'redir', op, fd }
 * Heredoc bodies are attached later as { type: 'heredoc', body }.
 */
export function tokenize(src) {
  const tokens = [];
  const nested = [];
  const pendingHeredocs = [];
  let i = 0;
  let word = null; // { value, raw, quoted, start }

  const startWord = () => {
    if (!word) word = { value: '', raw: '', quoted: false, start: i };
  };
  const endWord = () => {
    if (word) {
      word.raw = src.slice(word.start, i);
      tokens.push({ type: 'word', value: word.value, raw: word.raw, quoted: word.quoted });
      word = null;
    }
  };

  const consumeHeredocBodies = () => {
    // Called right after a newline has been consumed.
    while (pendingHeredocs.length) {
      const hd = pendingHeredocs.shift();
      const lines = [];
      while (i <= src.length) {
        const nl = src.indexOf('\n', i);
        const lineEnd = nl === -1 ? src.length : nl;
        const line = src.slice(i, lineEnd);
        i = nl === -1 ? src.length : nl + 1;
        const cmp = hd.stripTabs ? line.replace(/^\t+/, '') : line;
        if (cmp === hd.delimiter) break;
        lines.push(line);
        if (nl === -1) break;
      }
      hd.token.body = lines.join('\n');
    }
  };

  while (i < src.length) {
    const ch = src[i];

    // Line continuation
    if (ch === '\\' && src[i + 1] === '\n') { i += 2; continue; }

    if (ch === ' ' || ch === '\t' || ch === '\r') { endWord(); i++; continue; }

    if (ch === '\n') {
      endWord();
      tokens.push({ type: 'op', value: '\n' });
      i++;
      if (pendingHeredocs.length) consumeHeredocBodies();
      continue;
    }

    if (ch === '#' && !word) {
      const nl = src.indexOf('\n', i);
      i = nl === -1 ? src.length : nl;
      continue;
    }

    if (ch === "'") {
      startWord();
      const end = src.indexOf("'", i + 1);
      const stop = end === -1 ? src.length : end;
      word.value += src.slice(i + 1, stop);
      word.quoted = true;
      i = stop + 1;
      continue;
    }

    if (ch === '"') {
      startWord();
      word.quoted = true;
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\' && i + 1 < src.length && '"\\$`\n'.includes(src[i + 1])) {
          if (src[i + 1] !== '\n') word.value += src[i + 1];
          i += 2;
          continue;
        }
        if (src[i] === '$' && src[i + 1] === '(' && src[i + 2] !== '(') {
          const { inner, end } = readBalanced(src, i + 2);
          nested.push(inner);
          word.value += `$(${inner})`;
          i = end + 1;
          continue;
        }
        if (src[i] === '`') {
          const { inner, end } = readBacktick(src, i + 1);
          nested.push(inner);
          word.value += `\`${inner}\``;
          i = end + 1;
          continue;
        }
        word.value += src[i];
        i++;
      }
      i++; // closing quote
      continue;
    }

    if (ch === '\\') {
      startWord();
      if (i + 1 < src.length) word.value += src[i + 1];
      word.quoted = true;
      i += 2;
      continue;
    }

    if (ch === '$' && src[i + 1] === '(' && src[i + 2] !== '(') {
      startWord();
      const { inner, end } = readBalanced(src, i + 2);
      nested.push(inner);
      word.value += `$(${inner})`;
      i = end + 1;
      continue;
    }

    if (ch === '$' && src[i + 1] === '(' && src[i + 2] === '(') {
      // Arithmetic $(( ... )) — keep as an opaque word fragment.
      startWord();
      const { end } = readBalanced(src, i + 2);
      const close = src.indexOf(')', end + 1);
      const stop = close === -1 ? src.length : close;
      word.value += src.slice(i, stop + 1);
      i = stop + 1;
      continue;
    }

    if (ch === '`') {
      startWord();
      const { inner, end } = readBacktick(src, i + 1);
      nested.push(inner);
      word.value += `\`${inner}\``;
      i = end + 1;
      continue;
    }

    if ((ch === '<' || ch === '>') && src[i + 1] === '(' && !word) {
      const { inner, end } = readBalanced(src, i + 2);
      nested.push(inner);
      tokens.push({ type: 'word', value: `${ch}(${inner})`, raw: src.slice(i, end + 1), quoted: false, procSub: inner });
      i = end + 1;
      continue;
    }

    // Redirections (optionally preceded by an fd number, or &>)
    if (ch === '>' || ch === '<' || (ch === '&' && src[i + 1] === '>')) {
      let fd = null;
      if (word && /^\d+$/.test(word.value) && !word.quoted) {
        fd = word.value;
        word = null;
      } else {
        endWord();
      }
      let op = ch;
      let j = i + 1;
      if (ch === '&') { op = '&>'; j = i + 2; if (src[j] === '>') { op = '&>>'; j++; } }
      else if (ch === '>') {
        if (src[j] === '>') { op = '>>'; j++; }
        else if (src[j] === '|') { op = '>|'; j++; }
        else if (src[j] === '&') { op = '>&'; j++; }
      } else if (ch === '<') {
        if (src[j] === '<') {
          op = '<<'; j++;
          if (src[j] === '<') { op = '<<<'; j++; }
          else if (src[j] === '-') { op = '<<-'; j++; }
        } else if (src[j] === '&') { op = '<&'; j++; }
        else if (src[j] === '>') { op = '<>'; j++; }
      }
      tokens.push({ type: 'redir', op, fd });
      i = j;
      if (op === '<<' || op === '<<-') {
        // Read delimiter word now.
        while (src[i] === ' ' || src[i] === '\t') i++;
        let delim = '';
        while (i < src.length && !/[\s;&|<>()]/.test(src[i])) {
          if (src[i] === "'" || src[i] === '"') {
            const q = src[i];
            const end = src.indexOf(q, i + 1);
            const stop = end === -1 ? src.length : end;
            delim += src.slice(i + 1, stop);
            i = stop + 1;
          } else if (src[i] === '\\') {
            delim += src[i + 1] ?? '';
            i += 2;
          } else {
            delim += src[i];
            i++;
          }
        }
        const token = { type: 'heredoc', delimiter: delim, body: '' };
        tokens.push(token);
        pendingHeredocs.push({ delimiter: delim, stripTabs: op === '<<-', token });
      }
      continue;
    }

    // Control operators
    if (ch === '&' || ch === '|' || ch === ';' || ch === '(' || ch === ')') {
      endWord();
      const two = src.slice(i, i + 2);
      if (two === '&&' || two === '||' || two === '|&' || two === ';;') {
        tokens.push({ type: 'op', value: two });
        i += 2;
      } else {
        tokens.push({ type: 'op', value: ch });
        i++;
      }
      continue;
    }

    startWord();
    word.value += ch;
    i++;
  }
  endWord();
  return { tokens, nested };
}

const ASSIGNMENT_RE = /^[A-Za-z_][A-Za-z0-9_]*=/;

/**
 * Parse a command line into simple commands.
 * Each command: { argv, words, env, redirects, heredocs, pipeline, pipeIndex, raw }
 * - argv: unquoted word values (after removing assignments)
 * - words: the matching word tokens (to inspect quoting / raw text)
 * - pipeline: numeric id shared by commands connected with | or |&
 */
export function parse(src, depth = 0) {
  const { tokens, nested } = tokenize(String(src ?? ''));
  const commands = [];
  let current = null;
  let pipeline = 0;
  let pipeIndex = 0;

  const flush = () => {
    if (current && (current.words.length || current.redirects.length)) {
      // Drop leading shell keywords such as `if`, `then`, `do`, `!`.
      while (current.words.length && !current.words[0].quoted && SHELL_KEYWORDS.has(current.words[0].value)) {
        current.words.shift();
      }
      // Leading NAME=value assignments.
      while (current.words.length && !current.words[0].quoted && ASSIGNMENT_RE.test(current.words[0].value)) {
        const w = current.words.shift();
        const eq = w.value.indexOf('=');
        current.env[w.value.slice(0, eq)] = w.value.slice(eq + 1);
      }
      if (current.words.length && NON_EXEC_KEYWORDS.has(current.words[0].value) && !current.words[0].quoted) {
        // `for x in ...` header etc. – not an executed command.
        current.words = [];
      }
      current.argv = current.words.map((w) => w.value);
      if (current.argv.length || current.redirects.length) {
        current.pipeline = pipeline;
        current.pipeIndex = pipeIndex;
        commands.push(current);
      }
    }
    current = null;
  };

  const ensure = () => {
    if (!current) current = { argv: [], words: [], env: {}, redirects: [], heredocs: [], pipeline: 0, pipeIndex: 0 };
  };

  for (let t = 0; t < tokens.length; t++) {
    const tok = tokens[t];
    if (tok.type === 'op') {
      if (OPERATOR_SEPARATORS.has(tok.value)) {
        const hadCommand = current && current.words.length;
        flush();
        if ((tok.value === '|' || tok.value === '|&') && hadCommand) {
          pipeIndex++;
        } else {
          pipeline++;
          pipeIndex = 0;
        }
      }
      continue;
    }
    ensure();
    if (tok.type === 'redir') {
      const next = tokens[t + 1];
      if (next && next.type === 'heredoc') {
        current.heredocs.push(next);
        current.redirects.push({ op: tok.op, fd: tok.fd, target: next.delimiter, heredoc: next });
        t++;
      } else if (next && next.type === 'word') {
        current.redirects.push({ op: tok.op, fd: tok.fd, target: next.value, raw: next.raw });
        t++;
      } else {
        current.redirects.push({ op: tok.op, fd: tok.fd, target: '' });
      }
      continue;
    }
    if (tok.type === 'heredoc') {
      current.heredocs.push(tok);
      continue;
    }
    current.words.push(tok);
  }
  flush();

  return { commands, nested: depth < 6 ? nested : [] };
}

export function basename(p) {
  const s = String(p ?? '');
  const idx = s.lastIndexOf('/');
  return idx === -1 ? s : s.slice(idx + 1);
}

// Option arity for wrapper commands we "see through".
const SUDO_OPTS_WITH_ARG = new Set(['-u', '-g', '-h', '-p', '-C', '-U', '-r', '-t', '-T', '-D', '--user', '--group', '--host', '--prompt']);
const SSH_OPTS_WITH_ARG = new Set(['-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-p', '-Q', '-R', '-S', '-W', '-w', '-B', '-P']);
const XARGS_OPTS_WITH_ARG = new Set(['-n', '-I', '-i', '-P', '-L', '-l', '-d', '-E', '-e', '-s', '-a', '--max-args', '--max-procs', '--delimiter', '--arg-file', '--replace']);
const SHELLS = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'busybox']);

export function isShell(name) {
  return SHELLS.has(basename(name));
}

/**
 * Strip wrappers like sudo/env/nohup/timeout/xargs so rules see the real
 * command. Returns { argv, wrappers, inner } where `inner` is a nested command
 * string to analyse recursively (from `bash -c`, `eval`, `ssh host cmd`).
 */
export function unwrap(argv) {
  let a = [...argv];
  const wrappers = [];
  let inner = null;

  for (let guard = 0; guard < 12 && a.length; guard++) {
    const name = basename(a[0]);
    if (name === 'sudo' || name === 'doas') {
      wrappers.push(name);
      let k = 1;
      while (k < a.length && a[k].startsWith('-')) {
        if (a[k] === '--') { k++; break; }
        if (SUDO_OPTS_WITH_ARG.has(a[k])) k += 2; else k++;
      }
      a = a.slice(k);
      continue;
    }
    if (name === 'env') {
      wrappers.push(name);
      let k = 1;
      while (k < a.length && (a[k].startsWith('-') || ASSIGNMENT_RE.test(a[k]))) {
        if (a[k] === '-u' || a[k] === '--unset' || a[k] === '-C' || a[k] === '--chdir' || a[k] === '-S') k += 2; else k++;
      }
      // Bare `env` (only options/assignments) prints the environment.
      if (k >= a.length) return { argv: ['env'], wrappers, inner };
      a = a.slice(k);
      continue;
    }
    if (['nohup', 'exec', 'builtin', 'caffeinate', 'unbuffer'].includes(name)) {
      wrappers.push(name);
      a = a.slice(1);
      if (name === 'caffeinate') while (a.length && a[0].startsWith('-')) a = a.slice(1);
      continue;
    }
    if (name === 'command') {
      if (a[1] === '-v' || a[1] === '-V') return { argv: [], wrappers, inner };
      wrappers.push(name);
      a = a.slice(1);
      if (a[0] === '-p') a = a.slice(1);
      continue;
    }
    if (name === 'time') {
      wrappers.push(name);
      a = a.slice(1);
      while (a.length && a[0].startsWith('-')) a = a.slice(1);
      continue;
    }
    if (name === 'nice' || name === 'ionice' || name === 'stdbuf' || name === 'chrt' || name === 'taskset') {
      wrappers.push(name);
      let k = 1;
      while (k < a.length && a[k].startsWith('-')) {
        if (/^-[nNcp]$/.test(a[k])) k += 2; else k++;
      }
      if (name === 'chrt' || name === 'taskset') k++; // priority / mask
      a = a.slice(k);
      continue;
    }
    if (name === 'timeout' || name === 'gtimeout') {
      wrappers.push(name);
      let k = 1;
      while (k < a.length && a[k].startsWith('-')) {
        if (a[k] === '-s' || a[k] === '-k' || a[k] === '--signal' || a[k] === '--kill-after') k += 2; else k++;
      }
      a = a.slice(k + 1); // skip duration
      continue;
    }
    if (name === 'watch') {
      wrappers.push(name);
      let k = 1;
      while (k < a.length && a[k].startsWith('-')) {
        if (a[k] === '-n' || a[k] === '-d' || a[k] === '--interval') k += 2; else k++;
      }
      a = a.slice(k);
      if (a.length === 1) { inner = a[0]; return { argv: [], wrappers, inner }; }
      continue;
    }
    if (name === 'xargs') {
      wrappers.push(name);
      let k = 1;
      while (k < a.length && a[k].startsWith('-')) {
        if (XARGS_OPTS_WITH_ARG.has(a[k])) k += 2; else k++;
      }
      a = a.slice(k);
      if (!a.length) a = ['echo'];
      continue;
    }
    if (isShell(name)) {
      // bash -c 'cmd', bash -lc 'cmd', sh -ec 'cmd'
      for (let k = 1; k < a.length; k++) {
        const opt = a[k];
        if (opt === '-c' || (/^-[a-zA-Z]+$/.test(opt) && opt.includes('c') && !opt.startsWith('--'))) {
          if (k + 1 < a.length) inner = a[k + 1];
          return { argv: a, wrappers: [...wrappers, name], inner };
        }
        if (!opt.startsWith('-')) break;
      }
      return { argv: a, wrappers, inner };
    }
    if (name === 'eval') {
      wrappers.push(name);
      inner = a.slice(1).join(' ');
      return { argv: [], wrappers, inner };
    }
    if (name === 'ssh') {
      let k = 1;
      while (k < a.length && a[k].startsWith('-')) {
        if (SSH_OPTS_WITH_ARG.has(a[k])) k += 2; else k++;
      }
      // a[k] is host; the rest is the remote command
      if (k + 1 < a.length) inner = a.slice(k + 1).join(' ');
      return { argv: a, wrappers: [...wrappers, 'ssh'], inner, remote: true };
    }
    break;
  }
  return { argv: a, wrappers, inner };
}

/** Split combined short flags: `-rf` → ['r','f']; long flags kept as-is. */
export function flagSet(args) {
  const short = new Set();
  const long = new Set();
  for (const arg of args) {
    if (arg === '--') break;
    if (arg.startsWith('--')) long.add(arg.split('=')[0]);
    else if (arg.startsWith('-') && arg.length > 1) for (const c of arg.slice(1)) short.add(c);
  }
  return { short, long, has: (s, l) => (s && short.has(s)) || (l && long.has(l)) };
}

/** Positional (non-flag) args, honouring `--`. */
export function positionals(args) {
  const out = [];
  let endOfOpts = false;
  for (const arg of args) {
    if (!endOfOpts && arg === '--') { endOfOpts = true; continue; }
    if (!endOfOpts && arg.startsWith('-') && arg.length > 1) continue;
    out.push(arg);
  }
  return out;
}
