import { Finding, ScanContext } from "../types.js";

const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; severity: "critical" | "high" | "medium"; description: string }> = [
  {
    pattern: /rm\s+-rf\s+[\/~]/,
    severity: "critical",
    description: "Destructive rm -rf targeting root or home directory",
  },
  {
    pattern: /rm\s+-rf\s+\$/,
    severity: "high",
    description: "Destructive rm -rf with variable expansion — target depends on runtime",
  },
  {
    pattern: /mkfs\./,
    severity: "critical",
    description: "Filesystem format command — can wipe entire partitions",
  },
  {
    pattern: /dd\s+if=.*of=\/dev\//,
    severity: "critical",
    description: "dd writing directly to device — can overwrite disks",
  },
  {
    pattern: /chmod\s+(-R\s+)?777/,
    severity: "high",
    description: "Setting world-writable permissions — security risk",
  },
  {
    pattern: /chown\s+-R\s+.*\s+\//,
    severity: "high",
    description: "Recursive chown on root filesystem",
  },
  {
    pattern: />\s*\/etc\/(passwd|shadow|sudoers|hosts)/,
    severity: "critical",
    description: "Overwriting critical system file",
  },
  {
    pattern: /sudo\s+.*--no-preserve-env/,
    severity: "medium",
    description: "sudo with --no-preserve-env can be used to escalate privileges",
  },
  {
    pattern: /\bkill\s+-9\s+-1\b/,
    severity: "critical",
    description: "kill -9 -1 kills all user processes",
  },
  {
    pattern: /\b:?\(\)\s*\{\s*:?\|:?&\s*\}\s*;?\s*:?/,
    severity: "critical",
    description: "Fork bomb pattern detected",
  },
  {
    pattern: /shutdown|reboot|init\s+[06]/,
    severity: "high",
    description: "System shutdown/reboot command",
  },
  {
    pattern: /\biptables\b.*-F/,
    severity: "high",
    description: "Flushing iptables rules — disables firewall",
  },
  {
    pattern: /\bufw\s+disable\b/,
    severity: "high",
    description: "Disabling UFW firewall",
  },
  {
    pattern: /crontab\s+-r/,
    severity: "medium",
    description: "Removing all cron jobs",
  },
  {
    pattern: /\beval\b.*\$[\({]/,
    severity: "high",
    description: "eval with dynamic variable expansion — code injection risk",
  },
  {
    pattern: /\bnc\b.*-[le].*\b(sh|bash|zsh)\b/,
    severity: "critical",
    description: "Reverse shell via netcat",
  },
  {
    pattern: /\/dev\/(tcp|udp)\//,
    severity: "critical",
    description: "Bash /dev/tcp or /dev/udp — network connection used in reverse shells",
  },
];

export function scanShellCommands(ctx: ScanContext): Finding[] {
  const findings: Finding[] = [];

  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    for (const { pattern, severity, description } of DANGEROUS_PATTERNS) {
      if (pattern.test(line)) {
        findings.push({
          scanner: "shell-commands",
          severity,
          file: ctx.filePath,
          line: i + 1,
          matched: line.trim(),
          description,
        });
      }
    }
  }

  return findings;
}
