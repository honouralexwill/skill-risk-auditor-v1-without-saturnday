# skill-risk-auditor

An OpenClaw / Claude Code skill that inspects other skills for security risks before install or publish.

## What it does

Scans a skill directory and flags:

- **Shell commands** — `rm -rf /`, fork bombs, reverse shells, privilege escalation, firewall disabling
- **Curl-pipe-bash** — `curl | bash`, `wget | sh`, `source <(curl ...)`, eval of remote content
- **Obfuscation** — hex/octal escapes, base64-encoded payloads, `eval(atob(...))`, minified blobs, `String.fromCharCode`
- **Hardcoded secrets** — AWS keys, GitHub/Slack/npm tokens, private keys, passwords, DB connection strings
- **Suspicious domains** — shady TLDs (`.tk`, `.xyz`), raw IP URLs, URL shorteners, non-allowlisted external domains
- **Social engineering** — prompt injection ("ignore previous instructions"), persona hijacking, safety bypass instructions, data exfiltration commands

Outputs a plain English risk summary with severity scoring and optionally compares local files against a published version hash.

## Install

```bash
git clone https://github.com/honouralexwill/skill-risk-auditor-v1-without-saturnday.git
cd skill-risk-auditor-v1-without-saturnday
npm install
npm run build
```

## Usage

### CLI

```bash
# Human-readable report
node dist/audit.js <skill-path>

# JSON output
node dist/audit.js <skill-path> --json

# Compare against a published hash
node dist/audit.js <skill-path> --compare <sha256-hash>
```

### As a Claude Code skill

Copy or symlink this directory into your skills folder:

```bash
# Personal skill (available in all projects)
cp -r . ~/.claude/skills/skill-risk-auditor

# Project skill (available in one project)
cp -r . .claude/skills/skill-risk-auditor
```

Then invoke with:

```
/skill-risk-auditor ./path/to/skill
```

## Risk scoring

Each finding has a severity that contributes to the overall risk score (max 200):

| Severity | Points | Meaning |
|----------|--------|---------|
| Critical | 40 | Immediate danger — do not install |
| High | 20 | Likely malicious or very risky |
| Medium | 8 | Suspicious, may be legitimate |
| Low | 2 | Informational |

| Score | Risk level |
|-------|------------|
| 0 | CLEAN |
| 1–10 | LOW |
| 11–40 | MEDIUM |
| 41–100 | HIGH |
| 101–200 | CRITICAL |

## Example output

```
════════════════════════════════════════════════════════════
  SKILL RISK AUDIT REPORT
════════════════════════════════════════════════════════════

  Target:         /path/to/suspicious-skill
  Files scanned:  1
  Total findings: 14
  Risk score:     200 / 200
  Risk level:     CRITICAL

  FINDINGS BY SEVERITY
  ────────────────────────────────────────
  🔴 CRITICAL   6
  🟠 HIGH       6
  🟡 MEDIUM     1
  🔵 LOW        1

  ...

════════════════════════════════════════════════════════════
  PLAIN ENGLISH SUMMARY
════════════════════════════════════════════════════════════

  This skill has 6 CRITICAL issue(s) that pose serious security risks.
  DO NOT install or run this skill without thorough manual review.

════════════════════════════════════════════════════════════
```

## Project structure

```
├── SKILL.md                  # OpenClaw skill manifest
├── src/
│   ├── audit.ts              # CLI entry point
│   ├── types.ts              # Shared types
│   ├── reporter.ts           # Risk scoring + report generation
│   ├── hash-compare.ts       # SHA-256 hash comparison
│   └── scanners/
│       ├── shell-commands.ts  # 16 dangerous shell patterns
│       ├── curl-pipe.ts       # 13 curl-pipe-to-shell patterns
│       ├── obfuscation.ts     # 18 obfuscation patterns + heuristics
│       ├── secrets.ts         # 17 secret/credential patterns
│       ├── domains.ts         # Suspicious TLDs, raw IPs, shorteners
│       └── social-engineering.ts  # 19 prompt injection / manipulation patterns
└── test-fixtures/
    ├── malicious-skill/       # Test fixture (14 findings, CRITICAL)
    └── clean-skill/           # Test fixture (0 findings, CLEAN)
```

## License

MIT-0
