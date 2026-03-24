"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanObfuscation = scanObfuscation;
const OBFUSCATION_PATTERNS = [
    {
        pattern: /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}/,
        severity: "high",
        description: "Long hex-escaped string — likely obfuscated payload",
    },
    {
        pattern: /\\[0-7]{3}(\\[0-7]{3}){5,}/,
        severity: "high",
        description: "Long octal-escaped string — likely obfuscated payload",
    },
    {
        pattern: /\batob\s*\(/,
        severity: "medium",
        description: "Base64 decode (atob) — may hide payload content",
    },
    {
        pattern: /\bBuffer\.from\s*\([^)]+,\s*['"]base64['"]\s*\)/,
        severity: "medium",
        description: "Node.js base64 decode — may hide payload content",
    },
    {
        pattern: /base64\s+(-d|--decode)/,
        severity: "high",
        description: "Shell base64 decode — may hide commands",
    },
    {
        pattern: /echo\s+[A-Za-z0-9+\/=]{40,}\s*\|\s*base64\s+(-d|--decode)/,
        severity: "critical",
        description: "Encoded payload decoded and likely executed",
    },
    {
        pattern: /\beval\s*\(\s*atob/,
        severity: "critical",
        description: "eval of base64-decoded content — hidden code execution",
    },
    {
        pattern: /\beval\s*\(\s*Buffer\.from/,
        severity: "critical",
        description: "eval of Buffer-decoded content — hidden code execution",
    },
    {
        pattern: /\bString\.fromCharCode\s*\(\s*(\d+\s*,\s*){5,}/,
        severity: "high",
        description: "String.fromCharCode with many values — likely obfuscated string",
    },
    {
        pattern: /\bchar\s*\(\s*(\d+\s*,\s*){5,}/,
        severity: "high",
        description: "char() with many numeric codes — likely obfuscated string",
    },
    {
        pattern: /\['\\x[0-9a-f]{2}[^']*'\]/,
        severity: "medium",
        description: "Property access via hex escape — obfuscated method call",
    },
    {
        pattern: /\bFunction\s*\(\s*['"`]/,
        severity: "high",
        description: "Function constructor with string — dynamic code generation",
    },
    {
        pattern: /new\s+Function\s*\(/,
        severity: "high",
        description: "new Function() — dynamic code generation",
    },
    {
        pattern: /\bexec\s*\(\s*['"].*\\x/,
        severity: "critical",
        description: "exec with hex-escaped content — obfuscated command execution",
    },
    {
        pattern: /printf\s+['"]\\x[0-9a-f]/i,
        severity: "high",
        description: "printf with hex escapes — may reconstruct hidden commands",
    },
    {
        pattern: /\$'\\.+'/,
        severity: "medium",
        description: "ANSI-C quoting with escape sequences — can hide commands",
    },
    {
        pattern: /rev\s*<<<|<<<.*\|\s*rev/,
        severity: "medium",
        description: "String reversal — can be used to obfuscate commands",
    },
    {
        pattern: /\btr\b.*[A-Za-z].*[A-Za-z].*\|/,
        severity: "medium",
        description: "Character substitution (tr) piped — can deobfuscate ROT/cipher strings",
    },
];
function scanObfuscation(ctx) {
    const findings = [];
    for (let i = 0; i < ctx.lines.length; i++) {
        const line = ctx.lines[i];
        for (const { pattern, severity, description } of OBFUSCATION_PATTERNS) {
            if (pattern.test(line)) {
                findings.push({
                    scanner: "obfuscation",
                    severity,
                    file: ctx.filePath,
                    line: i + 1,
                    matched: line.trim().substring(0, 200),
                    description,
                });
            }
        }
    }
    // Check for suspiciously long single lines (minified/obfuscated)
    for (let i = 0; i < ctx.lines.length; i++) {
        const line = ctx.lines[i];
        if (line.length > 1000 && !/^\s*(\/\/|#|\/\*|\*|<!--)/.test(line)) {
            findings.push({
                scanner: "obfuscation",
                severity: "medium",
                file: ctx.filePath,
                line: i + 1,
                matched: `[line of ${line.length} characters]`,
                description: "Extremely long line — may be minified or obfuscated code",
            });
        }
    }
    // Check for high ratio of non-printable / unusual characters
    const nonPrintable = ctx.content.replace(/[\x20-\x7E\n\r\t]/g, "").length;
    const ratio = ctx.content.length > 0 ? nonPrintable / ctx.content.length : 0;
    if (ratio > 0.1 && ctx.content.length > 100) {
        findings.push({
            scanner: "obfuscation",
            severity: "high",
            file: ctx.filePath,
            line: 0,
            matched: `[${(ratio * 100).toFixed(1)}% non-printable characters]`,
            description: "High ratio of non-printable characters — file may contain binary or obfuscated content",
        });
    }
    return findings;
}
