# Changelog

## 0.1.0 (unreleased)

First public version.

- `PreToolUse` hook for Claude Code (`Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Read`) and Codex (`Bash`, `apply_patch`).
- Shell parser that understands quoting, pipelines, `&&`/`||`/`;`, subshells, `$(…)`, backticks, process substitution and heredocs, and sees through `sudo`, `env`, `nohup`, `timeout`, `xargs`, `bash -c`, `eval` and `ssh host cmd`.
- 29 built-in rules (plus your own deny/ask patterns) across files, disks, system, remote code, git, GitHub CLI, databases, infrastructure, releases, secrets and self-protection.
- Secret scanner: 23 provider-specific formats (including DB URLs with passwords) plus an entropy heuristic, inline `agent-guard: allow` pragma, redacted previews.
- `git commit` scans the staged diff, including `git add . && git commit` in the same command.
- Two-layer config (user + project) with a trust model: project files can only tighten the policy by default.
- Codex adaptation: "ask" becomes a deny with an instruction to get human confirmation (configurable).
- CLI: `hook`, `check`, `scan` (files or `--staged`), `rules`, `install claude|codex`, `doctor`.
- JSONL audit log with secrets redacted.
- Claude Code plugin + marketplace manifest, Codex plugin manifest.
