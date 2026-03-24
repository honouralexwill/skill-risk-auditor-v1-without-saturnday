import { Finding, ScanContext } from "../types.js";

const SE_PATTERNS: Array<{ pattern: RegExp; severity: "critical" | "high" | "medium" | "low"; description: string }> = [
  // Instructions that try to override safety
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|constraints?)/i,
    severity: "critical",
    description: "Prompt injection: attempts to override prior instructions",
  },
  {
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?)/i,
    severity: "critical",
    description: "Prompt injection: attempts to disregard prior instructions",
  },
  {
    pattern: /forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|context)/i,
    severity: "critical",
    description: "Prompt injection: attempts to clear prior context",
  },
  {
    pattern: /you\s+are\s+now\s+(a|an|in)\s+/i,
    severity: "high",
    description: "Role reassignment attempt — tries to change the AI's persona",
  },
  {
    pattern: /pretend\s+(you\s+are|to\s+be|you're)\s+/i,
    severity: "high",
    description: "Persona manipulation — asks AI to pretend to be something else",
  },
  {
    pattern: /act\s+as\s+(if\s+you\s+are|a|an)\s+/i,
    severity: "medium",
    description: "Persona manipulation — instructs AI to act as a different role",
  },

  // Urgency and pressure tactics
  {
    pattern: /do\s+(this|it)\s+(immediately|now|right\s+now|urgently|asap)\s+without\s+(checking|verifying|reviewing|asking)/i,
    severity: "high",
    description: "Pressure tactic — urges immediate action without verification",
  },
  {
    pattern: /skip\s+(all\s+)?(safety|security|verification|validation)\s+(checks?|steps?|measures?)/i,
    severity: "critical",
    description: "Instructs skipping safety checks",
  },
  {
    pattern: /don'?t\s+(bother|worry\s+about|need\s+to)\s+(check|verify|validate|review|read)/i,
    severity: "high",
    description: "Discourages verification — social engineering to skip review",
  },

  // Deception patterns
  {
    pattern: /this\s+is\s+(completely\s+)?(safe|harmless|normal|standard|routine)\s*(,|\.|;|\s)/i,
    severity: "medium",
    description: "Reassurance pattern — claims action is safe (often used to lower guard)",
  },
  {
    pattern: /trust\s+me/i,
    severity: "low",
    description: "Social engineering phrase: 'trust me'",
  },
  {
    pattern: /everyone\s+(does|uses)\s+this/i,
    severity: "low",
    description: "Social proof manipulation — 'everyone does this'",
  },

  // Permission escalation
  {
    pattern: /grant\s+(me\s+)?(full|admin|root|sudo|unlimited)\s+(access|permissions?|privileges?)/i,
    severity: "critical",
    description: "Requests elevated permissions",
  },
  {
    pattern: /run\s+(this\s+)?(as\s+)?(root|admin|administrator|sudo)/i,
    severity: "high",
    description: "Instructs running with elevated privileges",
  },
  {
    pattern: /disable\s+(all\s+)?(security|antivirus|firewall|protection|defender)/i,
    severity: "critical",
    description: "Instructs disabling security software",
  },

  // Exfiltration instructions
  {
    pattern: /send\s+(this|the|all|your)\s+(data|files?|info|information|credentials?|tokens?|keys?|secrets?)\s+to/i,
    severity: "critical",
    description: "Data exfiltration instruction — sends sensitive data externally",
  },
  {
    pattern: /upload\s+(this|the|all|your)\s+(data|files?|info|credentials?|tokens?|keys?)\s+to/i,
    severity: "critical",
    description: "Data exfiltration instruction via upload",
  },
  {
    pattern: /post\s+(this|the|all|your)\s+(data|content|output)\s+to/i,
    severity: "medium",
    description: "Possible data exfiltration — posts content to external endpoint",
  },

  // Hidden instruction patterns
  {
    pattern: /<!--.*(?:ignore|override|skip|disable|execute).*-->/i,
    severity: "high",
    description: "Suspicious instruction hidden inside HTML comment",
  },
  {
    pattern: /\[comment\]:\s*#\s*\(.*(?:ignore|override|execute).*\)/i,
    severity: "high",
    description: "Suspicious instruction hidden in markdown comment",
  },

  // Tool abuse patterns
  {
    pattern: /\ballow[-_]?tool\b.*\bBash\b/i,
    severity: "medium",
    description: "Attempts to allowlist Bash tool — may enable arbitrary command execution",
  },
  {
    pattern: /dangerouslyDisableSandbox/i,
    severity: "critical",
    description: "References sandbox bypass — extremely dangerous if executed",
  },
];

export function scanSocialEngineering(ctx: ScanContext): Finding[] {
  const findings: Finding[] = [];

  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    for (const { pattern, severity, description } of SE_PATTERNS) {
      if (pattern.test(line)) {
        findings.push({
          scanner: "social-engineering",
          severity,
          file: ctx.filePath,
          line: i + 1,
          matched: line.trim().substring(0, 200),
          description,
        });
      }
    }
  }

  return findings;
}
