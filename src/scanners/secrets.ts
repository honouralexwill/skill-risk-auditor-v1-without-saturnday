import { Finding, ScanContext } from "../types.js";

const SECRET_PATTERNS: Array<{ pattern: RegExp; severity: "critical" | "high" | "medium"; description: string }> = [
  // API keys with common prefixes
  {
    pattern: /\b(sk|pk)[-_](live|test|prod)[-_][A-Za-z0-9]{20,}/,
    severity: "critical",
    description: "Likely API secret key (sk-live/pk-live pattern)",
  },
  {
    pattern: /\bsk-[A-Za-z0-9]{32,}/,
    severity: "critical",
    description: "Possible OpenAI/Stripe-style secret key",
  },
  {
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    severity: "critical",
    description: "AWS Access Key ID detected",
  },
  {
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/,
    severity: "critical",
    description: "Google API key detected",
  },
  {
    pattern: /\bghp_[A-Za-z0-9]{36}\b/,
    severity: "critical",
    description: "GitHub personal access token detected",
  },
  {
    pattern: /\bgho_[A-Za-z0-9]{36}\b/,
    severity: "critical",
    description: "GitHub OAuth token detected",
  },
  {
    pattern: /\bghs_[A-Za-z0-9]{36}\b/,
    severity: "critical",
    description: "GitHub server-to-server token detected",
  },
  {
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/,
    severity: "critical",
    description: "GitLab personal access token detected",
  },
  {
    pattern: /\bxox[bpors]-[A-Za-z0-9-]{10,}/,
    severity: "critical",
    description: "Slack token detected",
  },
  {
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/,
    severity: "critical",
    description: "npm access token detected",
  },
  {
    pattern: /\bpypi-[A-Za-z0-9_-]{50,}\b/,
    severity: "critical",
    description: "PyPI API token detected",
  },

  // Generic secret patterns
  {
    pattern: /['"]?(?:api[_-]?key|api[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)['"]?\s*[:=]\s*['"][A-Za-z0-9+\/=_-]{16,}['"]/i,
    severity: "high",
    description: "Hardcoded API key or secret assignment",
  },
  {
    pattern: /['"]?password['"]?\s*[:=]\s*['"][^'"]{8,}['"]/i,
    severity: "high",
    description: "Hardcoded password assignment",
  },
  {
    pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/,
    severity: "critical",
    description: "Private key embedded in file",
  },
  {
    pattern: /-----BEGIN\s+CERTIFICATE-----/,
    severity: "medium",
    description: "Certificate embedded in file (check if intentional)",
  },

  // Database connection strings with credentials
  {
    pattern: /(mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@/i,
    severity: "high",
    description: "Database connection string with embedded credentials",
  },

  // Bearer tokens
  {
    pattern: /['"]Bearer\s+[A-Za-z0-9._-]{20,}['"]/,
    severity: "high",
    description: "Hardcoded Bearer token",
  },
];

export function scanSecrets(ctx: ScanContext): Finding[] {
  const findings: Finding[] = [];

  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];

    // Skip obvious comments and documentation
    const trimmed = line.trim();
    if (trimmed.startsWith("//") && trimmed.includes("example")) continue;
    if (trimmed.startsWith("#") && trimmed.includes("example")) continue;

    for (const { pattern, severity, description } of SECRET_PATTERNS) {
      if (pattern.test(line)) {
        // Redact the matched value in output
        const redacted = line.trim().replace(/([A-Za-z0-9+\/=_-]{8})[A-Za-z0-9+\/=_-]{8,}/g, "$1********");
        findings.push({
          scanner: "secrets",
          severity,
          file: ctx.filePath,
          line: i + 1,
          matched: redacted.substring(0, 200),
          description,
        });
      }
    }
  }

  return findings;
}
