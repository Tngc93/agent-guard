# Security policy

## Scope

agent-guard is a defense-in-depth layer, not a sandbox (see "Limitations" in the README). Reports are especially welcome for:

- **Bypasses:** a plainly destructive command that an agent would realistically produce, which agent-guard allows. For example, a common wrapper or quoting form we do not unwrap.
- **Tampering:** a way for the agent or a cloned repository to disable or loosen the policy without the user noticing.
- **Leaks:** secret values appearing in hook output, reasons shown to the agent, or the audit log.
- **Crashes on valid input** that make the hook fail open.

Hand-crafted obfuscation (computing a program name from many fragments, compiled binaries) is a known limitation of static analysis. Concrete proposals to cover more of it are still welcome.

## Reporting

Please open a [private security advisory](https://github.com/Tngc93/agent-guard/security/advisories/new) instead of a public issue. Include the exact command or hook payload, what agent-guard decided, and what you expected.

## Supported versions

Only the latest release receives fixes.
