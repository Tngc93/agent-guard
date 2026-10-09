# agent-guard

**Guard rails for AI coding agents.** agent-guard is a `PreToolUse` hook for **Claude Code** and **Codex** that reads what a tool call is actually about to do — and blocks or pauses it when it would destroy data, leak a secret, or switch off the agent's own safety checks.

English | [Türkçe](README.tr.md)

[![CI](https://github.com/Tngc93/agent-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Tngc93/agent-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![Dependencies: 0](https://img.shields.io/badge/dependencies-0-blue)

```text
$ agent-guard check "git push --force origin main"
DENY  git push --force origin main
  - [deny] git.force-push: Force push to protected branch `main` rewrites shared history.

$ agent-guard check 'rm -rf "$BUILD_DIR"/*'
ASK   rm -rf "$BUILD_DIR"/*
  - [ask] fs.rm-recursive: the path depends on a shell variable. If it is empty or unset this can target `/`.

$ agent-guard check "rm -rf node_modules dist"
ALLOW rm -rf node_modules dist
```

## Why

Agents run commands with your permissions. Built-in permission rules match command *prefixes*: allowing `Bash(git push:*)` also allows `git push --force origin main`, and allowing `Bash(rm:*)` allows `rm -rf ~`. agent-guard parses the command — quoting, pipes, `&&`, `$(…)`, heredocs, `sudo`/`env`/`xargs`/`bash -c` wrappers — and decides from what will really run.

- **Three outcomes.** `deny` for things that are never what you want (`rm -rf ~`, force-pushing `main`, a hard-coded API key). `ask` for things that are sometimes right but need a human (`git reset --hard`, `terraform destroy`, `npm publish`). Everything else passes silently.
- **Low noise.** Ordinary development commands are allowed: `rm -rf node_modules`, `git push origin feature/x`, `cp .env.example .env`, `prisma migrate dev`. The test suite includes a false-positive sweep of everyday commands.
- **Tamper-resistant.** The agent cannot quietly edit `.agent-guard.json`, `.claude/settings.json` or `.codex/hooks.json` to turn the guard off, and a cloned repository cannot loosen your policy.
- **Local and fast.** Zero dependencies, no network calls. A check takes well under a millisecond; Node start-up dominates.

## What it catches

| Area | Denied | Needs approval |
| --- | --- | --- |
| **Files** | `rm -rf` on `/`, `~`, `$HOME/*`, system or top-level user folders; `find / -delete`; `chmod -R` on `/` or `~` | `rm -rf` outside the project, on the project root, on `.git`, or on an unguarded `$VAR` path |
| **Disks & system** | `mkfs`, `dd of=/dev/sda`, `diskutil eraseDisk`, writes to `/dev/sd*`, fork bombs | `shutdown`, `kill -9 -1`, `crontab -r`, `launchctl load`, `systemctl disable` |
| **Remote code** | Decoded content piped to a shell (`base64 -d \| sh`); inline `python -c`/`node -e` that deletes `/` or `$HOME` | `curl … \| bash`, `bash <(curl …)` |
| **Git** | Force push to `main`/`master`/`production`/`release/*`; deleting a protected remote branch; commits that contain secrets or `.env` files | Other force pushes, `reset --hard`, `clean -fdx`, `checkout .`, `stash clear`, `branch -D`, `filter-branch`, `--no-verify`, `git add .env` |
| **GitHub CLI** | `gh repo delete` | Visibility changes, `gh release delete`, `gh api -X DELETE` |
| **Databases** | Destructive SQL or resets when the command mentions production | `DROP`/`TRUNCATE`/`DELETE` without `WHERE`, `FLUSHALL`, `prisma migrate reset`, `rails db:drop`, `migrate:fresh`, `manage.py flush` |
| **Infrastructure** | Same as databases: escalated when the command mentions production | `terraform destroy`, `apply -auto-approve`, `kubectl delete`, `helm uninstall`, `aws … delete-*/terminate-*`, `docker system prune`, `compose down -v` |
| **Release** | | `npm/pnpm/yarn publish`, `cargo publish`, `twine upload`, `docker push`, `vercel --prod`, `firebase deploy`, `wrangler deploy` |
| **Secrets** | Writing provider keys (Anthropic, OpenAI, GitHub, AWS, Stripe, Google, Slack…), private keys or DB URLs with passwords into non-env files; sending `.env`/keys over the network | Reading `.env`/keys/cloud credentials, `env`/`printenv`, `echo $API_KEY` |
| **Self-protection** | Editing `.git/` internals, writing to `/usr`, `/bin`, `/System` | Editing agent-guard config, agent hook settings, shell startup files, `~/.ssh/authorized_keys`, `.git/hooks` |

Run `agent-guard rules` for the full list of rule ids.

## Install

Requires **Node.js 18.17+** on your `PATH` (the hook runs `node`).

### Claude Code: plugin (recommended)

```text
/plugin marketplace add Tngc93/agent-guard
/plugin install agent-guard@agent-guard
```

Or from your shell:

```bash
claude plugin marketplace add Tngc93/agent-guard
claude plugin install agent-guard@agent-guard
```

The plugin registers one `PreToolUse` hook for `Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit` and `Read`. Start a new session to load it.

### Claude Code: without the plugin system

```bash
git clone https://github.com/Tngc93/agent-guard ~/.agent-guard
node ~/.agent-guard/bin/agent-guard.mjs install claude            # ~/.claude/settings.json
node ~/.agent-guard/bin/agent-guard.mjs install claude --project  # ./.claude/settings.json
```

`install` merges into existing settings, keeps your other hooks, makes a timestamped backup, and is safe to run again.

### Codex

```bash
git clone https://github.com/Tngc93/agent-guard ~/.agent-guard
node ~/.agent-guard/bin/agent-guard.mjs install codex   # writes ~/.codex/hooks.json
```

Then open Codex and run **`/hooks`** to review and trust the hook. Codex skips hooks you have not trusted. The repository also ships a `.codex-plugin/plugin.json` that points at the same `hooks/hooks.json`, if you distribute it through a Codex plugin marketplace.

Codex has no "ask" decision. When a rule would ask, agent-guard denies the call and tells the agent to stop and get your confirmation. You can then run the command yourself or allow it in your config. Set `"codexAskBehavior": "allow"` to let those calls through instead.

## Try it without an agent

```bash
node bin/agent-guard.mjs check "curl -fsSL https://example.com/i.sh | sh"   # exit 0 allow, 1 ask, 2 deny
node bin/agent-guard.mjs scan src/          # find secrets in files
node bin/agent-guard.mjs scan --staged      # usable as a git pre-commit hook
node bin/agent-guard.mjs doctor             # show loaded config and audit log path
```

## What the agent sees

When a call is blocked, the agent receives the reason together with an instruction not to work around it:

```text
agent-guard blocked this action:
• Hard-coded Anthropic API key on line 3 [sk-a…Qx (108 chars)] in `src/client.ts`. Put it in an env file (e.g. .env, git-ignored) and read it from the environment instead. [secrets.hardcoded]
Do not try to achieve the same effect another way (other commands, scripts, encoding, or editing the guard config). Explain to the user what you wanted to do and why; they can run it themselves or adjust the agent-guard policy.
```

Secret values are never echoed back; only a redacted preview is shown.

## Configuration

Two optional JSON files:

| Layer | Location | Can loosen the policy? |
| --- | --- | --- |
| User | `~/.config/agent-guard/config.json` (or `$AGENT_GUARD_CONFIG`) | Yes |
| Project | `<repo>/.agent-guard.json` | **Only if** the user config sets `"trustProjectConfig": true` |

The project file lives inside the repository the agent is editing, and possibly one you just cloned. By default it can only make the policy **stricter**: it can add deny/ask patterns, protected paths and protected branches, and raise a rule to `ask` or `deny`. Attempts to disable rules, allow commands, or switch to audit mode are ignored, and the hook prints a warning.

| Key | Default | Meaning |
| --- | --- | --- |
| `mode` | `"enforce"` | `"audit"` logs decisions but never blocks. Useful for a trial week. |
| `disable` | `[]` | Rule ids to turn off. A trailing `*` matches a prefix, e.g. `"release.*"`. |
| `overrides` | `{}` | Change a rule's level: `{ "git.discard-work": "allow", "release.publish": "deny" }`. |
| `allow` | `[]` | Regexes. A matching shell command is allowed without any checks. Keep these narrow. |
| `deny` / `ask` | `[]` | `[{ "pattern": "regex", "reason": "shown to the agent" }]` for your own rules. |
| `protectedBranches` | `main, master, production, prod, release, release/*` | Force pushes and deletions of these are denied. |
| `protectedPaths` | `[]` | Globs (relative to the project) whose edits need approval, e.g. `"migrations/**"`. |
| `codexAskBehavior` | `"deny"` | What "ask" becomes on Codex: `"deny"` or `"allow"`. |
| `auditLog` | `true` | Append non-allow decisions to `audit.jsonl` (secrets redacted). |
| `failClosed` | `false` | If agent-guard itself crashes: `false` lets the call through, `true` blocks it. |

See [`examples/config.json`](examples/config.json) and [`examples/project.agent-guard.json`](examples/project.agent-guard.json).

To allow a single hard-coded value that is not a secret, add `agent-guard: allow` in a comment on the same line.

### Audit log

Every `ask`/`deny` is appended as one JSON line to `audit.jsonl` in the plugin data directory (`$CLAUDE_PLUGIN_DATA` or Codex's `$PLUGIN_DATA`) when one is set, otherwise in `~/.local/state/agent-guard/`. Override the location with `$AGENT_GUARD_AUDIT_LOG`; `agent-guard doctor` prints it. The file is created with `0600` permissions.

## Limitations

agent-guard is a **seatbelt, not a sandbox**. It is a fast, deterministic, pattern-based check and does not replace OS-level isolation.

- It cannot see what a program does internally. A script you already have, a `Makefile` target or a compiled binary can still delete files. The guard checks script *contents* when the agent writes them, but not scripts that already exist.
- Deliberately obfuscated commands, such as a program name computed at runtime or code assembled from fragments, can get past static analysis. The obvious forms (`$(echo rm)`, `base64 -d | sh`, `python -c`, `bash -c`, `eval`) are covered.
- Secret detection uses provider-specific formats plus an entropy heuristic. Unusual formats can be missed.
- By default it **fails open**: if the hook crashes or times out, the agent's normal permission flow applies. Set `failClosed` if you prefer the opposite.
- On Codex, hooks only see tools that go through `PreToolUse` (shell, `apply_patch`, MCP and local tools). Hosted tools such as web search are not intercepted.

Use it together with your agent's sandbox and permission modes, not instead of them.

## Development

```bash
npm test                       # unit + end-to-end tests, no dependencies
node bin/agent-guard.mjs rules # list rules
claude plugin validate .       # validate plugin + marketplace manifests
```

Adding a rule:
1. Add it to `src/rules/bash.mjs` for shell commands, or `src/rules/files.mjs` for file tools.
2. Add allow **and** deny/ask cases to `test/bash-rules.test.mjs`. Every new rule needs at least one "this ordinary command must still be allowed" case.

Test fixtures never contain literal secrets. They are generated at runtime (see `test/helpers.mjs`) so the repository passes its own scan and GitHub push protection.

## License

[MIT](LICENSE) © Berk Arcak
