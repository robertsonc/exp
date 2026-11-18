# CR-wp6-enrol-token-not-argv

**What:** `exp-agent enrol <token>` in docs/spec/06-agent.md section 8 (and line ~146) is replaced by
`exp-agent enrol [--manager URL] [--token-file PATH|-]`; the token is read from `$EXP_ENROL_TOKEN` or stdin.

**Why:** section 6 and SR-14 forbid secrets in argv (visible in /proc/<pid>/cmdline); the one-time enrol token is a secret.

**Affected WPs:** WP-6 (implemented), WP-7 (any packaging or docs that print `exp-agent enrol <token>`), manager UI hints.

**Compatibility:** install.sh is unaffected (token goes via a pipe to curl). A positional token is now a usage error (exit 2).
