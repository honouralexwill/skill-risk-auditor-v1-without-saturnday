"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanDomains = scanDomains;
// Known suspicious TLDs and domain patterns
const SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".work",
    ".click",
    ".loan",
    ".racing",
    ".win",
    ".bid",
    ".stream",
    ".download",
    ".accountant",
    ".science",
    ".date",
    ".faith",
    ".review",
    ".party",
    ".trade",
    ".webcam",
    ".cricket",
];
// Trusted domains that should not be flagged
const TRUSTED_DOMAINS = new Set([
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "npmjs.com",
    "registry.npmjs.org",
    "pypi.org",
    "crates.io",
    "rubygems.org",
    "brew.sh",
    "formulae.brew.sh",
    "golang.org",
    "pkg.go.dev",
    "developer.mozilla.org",
    "stackoverflow.com",
    "docs.github.com",
    "code.visualstudio.com",
    "marketplace.visualstudio.com",
    "anthropic.com",
    "claude.ai",
    "openai.com",
    "google.com",
    "googleapis.com",
    "microsoft.com",
    "apple.com",
    "docker.com",
    "docker.io",
    "hub.docker.com",
    "nodejs.org",
    "deno.land",
    "bun.sh",
    "rust-lang.org",
    "python.org",
    "wikipedia.org",
    "example.com",
    "localhost",
    "agentskills.io",
    "openclaw.ai",
]);
const DOMAIN_REGEX = /https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
const IP_URL_REGEX = /https?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
function isDomainTrusted(domain) {
    const lower = domain.toLowerCase();
    for (const trusted of TRUSTED_DOMAINS) {
        if (lower === trusted || lower.endsWith("." + trusted)) {
            return true;
        }
    }
    return false;
}
function hasSuspiciousTLD(domain) {
    const lower = domain.toLowerCase();
    return SUSPICIOUS_TLDS.some((tld) => lower.endsWith(tld));
}
function scanDomains(ctx) {
    const findings = [];
    for (let i = 0; i < ctx.lines.length; i++) {
        const line = ctx.lines[i];
        // Check for URLs with domains
        let match;
        const domainRegex = new RegExp(DOMAIN_REGEX.source, "g");
        while ((match = domainRegex.exec(line)) !== null) {
            const domain = match[1];
            if (isDomainTrusted(domain))
                continue;
            if (hasSuspiciousTLD(domain)) {
                findings.push({
                    scanner: "domains",
                    severity: "high",
                    file: ctx.filePath,
                    line: i + 1,
                    matched: line.trim().substring(0, 200),
                    description: `URL with suspicious TLD: ${domain}`,
                });
            }
            else {
                findings.push({
                    scanner: "domains",
                    severity: "low",
                    file: ctx.filePath,
                    line: i + 1,
                    matched: line.trim().substring(0, 200),
                    description: `External URL to non-allowlisted domain: ${domain}`,
                });
            }
        }
        // Check for raw IP URLs
        const ipRegex = new RegExp(IP_URL_REGEX.source, "g");
        while ((match = ipRegex.exec(line)) !== null) {
            const ip = match[1];
            if (ip === "127.0.0.1" || ip === "0.0.0.0")
                continue;
            findings.push({
                scanner: "domains",
                severity: "high",
                file: ctx.filePath,
                line: i + 1,
                matched: line.trim().substring(0, 200),
                description: `URL pointing to raw IP address: ${ip} — may be ephemeral C2 server`,
            });
        }
        // Check for URL shorteners
        const shortenerPattern = /https?:\/\/(bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|v\.gd|buff\.ly|ow\.ly|short\.io|rb\.gy)\//;
        if (shortenerPattern.test(line)) {
            findings.push({
                scanner: "domains",
                severity: "high",
                file: ctx.filePath,
                line: i + 1,
                matched: line.trim().substring(0, 200),
                description: "URL shortener used — hides the true destination",
            });
        }
    }
    return findings;
}
