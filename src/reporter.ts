import { AuditResult, Finding, Severity } from "./types.js";

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 2,
  info: 0,
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function riskLevel(score: number): string {
  if (score === 0) return "CLEAN";
  if (score <= 10) return "LOW";
  if (score <= 40) return "MEDIUM";
  if (score <= 100) return "HIGH";
  return "CRITICAL";
}

function groupBySeverity(findings: Finding[]): Map<Severity, Finding[]> {
  const map = new Map<Severity, Finding[]>();
  for (const sev of SEVERITY_ORDER) {
    map.set(sev, []);
  }
  for (const f of findings) {
    map.get(f.severity)!.push(f);
  }
  return map;
}

function groupByScanner(findings: Finding[]): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!map.has(f.scanner)) map.set(f.scanner, []);
    map.get(f.scanner)!.push(f);
  }
  return map;
}

export function computeRiskScore(findings: Finding[]): number {
  let score = 0;
  for (const f of findings) {
    score += SEVERITY_WEIGHT[f.severity];
  }
  return Math.min(score, 200);
}

export function generateReport(result: AuditResult): string {
  const lines: string[] = [];
  const bar = "═".repeat(60);

  lines.push(bar);
  lines.push("  SKILL RISK AUDIT REPORT");
  lines.push(bar);
  lines.push("");
  lines.push(`  Target:         ${result.targetPath}`);
  lines.push(`  Files scanned:  ${result.scannedFiles}`);
  lines.push(`  Total findings: ${result.findings.length}`);
  lines.push(`  Risk score:     ${result.riskScore} / 200`);
  lines.push(`  Risk level:     ${result.riskLevel}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("  ✔ No issues detected. This skill looks clean.");
    lines.push("");
    lines.push(bar);
    return lines.join("\n");
  }

  // Summary by severity
  const bySeverity = groupBySeverity(result.findings);
  lines.push("  FINDINGS BY SEVERITY");
  lines.push("  " + "─".repeat(40));
  for (const sev of SEVERITY_ORDER) {
    const count = bySeverity.get(sev)!.length;
    if (count > 0) {
      const icon = sev === "critical" ? "🔴" : sev === "high" ? "🟠" : sev === "medium" ? "🟡" : sev === "low" ? "🔵" : "⚪";
      lines.push(`  ${icon} ${sev.toUpperCase().padEnd(10)} ${count}`);
    }
  }
  lines.push("");

  // Summary by scanner
  const byScanner = groupByScanner(result.findings);
  lines.push("  FINDINGS BY CATEGORY");
  lines.push("  " + "─".repeat(40));
  for (const [scanner, findings] of byScanner) {
    lines.push(`  • ${scanner}: ${findings.length} finding(s)`);
  }
  lines.push("");

  // Detailed findings (grouped by severity)
  lines.push("  DETAILED FINDINGS");
  lines.push("  " + "─".repeat(40));
  for (const sev of SEVERITY_ORDER) {
    const items = bySeverity.get(sev)!;
    if (items.length === 0) continue;

    lines.push("");
    lines.push(`  [${sev.toUpperCase()}]`);
    for (const f of items) {
      lines.push("");
      lines.push(`    Scanner: ${f.scanner}`);
      lines.push(`    File:    ${f.file}:${f.line}`);
      lines.push(`    Issue:   ${f.description}`);
      lines.push(`    Match:   ${f.matched}`);
    }
  }

  lines.push("");

  // Plain English summary
  lines.push(bar);
  lines.push("  PLAIN ENGLISH SUMMARY");
  lines.push(bar);
  lines.push("");
  lines.push(`  ${result.summary}`);
  lines.push("");
  lines.push(bar);

  return lines.join("\n");
}

export function generateSummary(findings: Finding[]): string {
  if (findings.length === 0) {
    return "This skill appears safe. No risky patterns, secrets, or suspicious content were detected.";
  }

  const bySeverity = groupBySeverity(findings);
  const byScanner = groupByScanner(findings);
  const critCount = bySeverity.get("critical")!.length;
  const highCount = bySeverity.get("high")!.length;

  const parts: string[] = [];

  if (critCount > 0) {
    parts.push(
      `This skill has ${critCount} CRITICAL issue(s) that pose serious security risks.`
    );
  }

  if (highCount > 0) {
    parts.push(
      `There are ${highCount} HIGH severity issue(s) that warrant careful review.`
    );
  }

  // Describe each scanner category found
  const scannerDescriptions: Record<string, string> = {
    "shell-commands": "dangerous shell commands that could damage your system",
    "curl-pipe": "curl-pipe-to-shell patterns that execute remote code without inspection",
    obfuscation: "obfuscated or encoded content that hides its true purpose",
    secrets: "hardcoded secrets, API keys, or credentials",
    domains: "connections to suspicious or non-allowlisted external domains",
    "social-engineering": "social engineering or prompt injection patterns designed to manipulate AI behavior",
  };

  const categories: string[] = [];
  for (const [scanner] of byScanner) {
    if (scanner in scannerDescriptions) {
      categories.push(scannerDescriptions[scanner]);
    }
  }

  if (categories.length > 0) {
    parts.push(`Specifically, it contains: ${categories.join("; ")}.`);
  }

  if (critCount > 0) {
    parts.push("DO NOT install or run this skill without thorough manual review.");
  } else if (highCount > 0) {
    parts.push("Review the flagged items carefully before installing.");
  } else {
    parts.push("The issues found are low-to-medium severity. Review them but they may be benign.");
  }

  return parts.join(" ");
}
