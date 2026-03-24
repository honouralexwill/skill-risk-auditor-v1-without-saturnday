"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanCurlPipe = scanCurlPipe;
const CURL_PIPE_PATTERNS = [
    {
        pattern: /curl\s+[^|]*\|\s*(sudo\s+)?(ba)?sh/,
        severity: "critical",
        description: "curl piped to shell — executes remote code without inspection",
    },
    {
        pattern: /wget\s+[^|]*\|\s*(sudo\s+)?(ba)?sh/,
        severity: "critical",
        description: "wget piped to shell — executes remote code without inspection",
    },
    {
        pattern: /curl\s+[^|]*\|\s*(sudo\s+)?python/,
        severity: "critical",
        description: "curl piped to python — executes remote code without inspection",
    },
    {
        pattern: /curl\s+[^|]*\|\s*(sudo\s+)?node/,
        severity: "critical",
        description: "curl piped to node — executes remote code without inspection",
    },
    {
        pattern: /curl\s+[^|]*\|\s*(sudo\s+)?perl/,
        severity: "critical",
        description: "curl piped to perl — executes remote code without inspection",
    },
    {
        pattern: /curl\s+[^|]*\|\s*(sudo\s+)?ruby/,
        severity: "critical",
        description: "curl piped to ruby — executes remote code without inspection",
    },
    {
        pattern: /\$\(curl\s/,
        severity: "high",
        description: "Command substitution with curl — executes curl output as command",
    },
    {
        pattern: /`curl\s/,
        severity: "high",
        description: "Backtick execution of curl output — executes remote content",
    },
    {
        pattern: /curl\b.*-o\s*-\s*\|/,
        severity: "high",
        description: "curl output piped to another command",
    },
    {
        pattern: /wget\s+.*-O\s*-\s*\|/,
        severity: "high",
        description: "wget output piped to another command",
    },
    {
        pattern: /curl\b.*\beval\b/,
        severity: "critical",
        description: "curl combined with eval — remote code execution",
    },
    {
        pattern: /source\s+<\(curl/,
        severity: "critical",
        description: "Sourcing remote script via process substitution",
    },
    {
        pattern: /\.\s+<\(curl/,
        severity: "critical",
        description: "Dot-sourcing remote script via process substitution",
    },
];
function scanCurlPipe(ctx) {
    const findings = [];
    for (let i = 0; i < ctx.lines.length; i++) {
        const line = ctx.lines[i];
        for (const { pattern, severity, description } of CURL_PIPE_PATTERNS) {
            if (pattern.test(line)) {
                findings.push({
                    scanner: "curl-pipe",
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
