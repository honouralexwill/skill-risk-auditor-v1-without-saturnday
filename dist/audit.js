#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
const index_js_1 = require("./scanners/index.js");
const reporter_js_1 = require("./reporter.js");
const hash_compare_js_1 = require("./hash-compare.js");
// --- File collection ---
const TEXT_EXTENSIONS = new Set([
    ".md", ".ts", ".js", ".mjs", ".cjs", ".jsx", ".tsx",
    ".json", ".yaml", ".yml", ".sh", ".bash", ".zsh",
    ".py", ".rb", ".go", ".rs", ".toml", ".txt",
    ".cfg", ".ini", ".env", ".html", ".css", ".xml",
    ".csv", ".sql", ".lua", ".pl", ".php", ".java",
    ".kt", ".swift", ".c", ".cpp", ".h", ".hpp",
    ".makefile", ".dockerfile",
]);
const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", "__pycache__",
    ".venv", "venv", ".tox", "target", "vendor",
]);
function collectFiles(dir) {
    const results = [];
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    }
    catch {
        return results;
    }
    for (const entry of entries) {
        if (entry.name.startsWith(".") && entry.name !== ".env")
            continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            if (!SKIP_DIRS.has(entry.name)) {
                results.push(...collectFiles(fullPath));
            }
        }
        else if (entry.isFile()) {
            const ext = path.extname(entry.name).toLowerCase();
            const basename = entry.name.toLowerCase();
            if (TEXT_EXTENSIONS.has(ext) ||
                basename === "skill.md" ||
                basename === "makefile" ||
                basename === "dockerfile" ||
                basename === "rakefile" ||
                basename === "gemfile" ||
                basename === "procfile" ||
                ext === "") {
                // Only include files under 1MB
                try {
                    const stats = fs.statSync(fullPath);
                    if (stats.size < 1_000_000) {
                        results.push(fullPath);
                    }
                }
                catch {
                    // skip unreadable files
                }
            }
        }
    }
    return results;
}
// --- Audit logic ---
function auditSkill(targetPath) {
    const resolvedPath = path.resolve(targetPath);
    if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: path does not exist: ${resolvedPath}`);
        process.exit(1);
    }
    const stat = fs.statSync(resolvedPath);
    let files;
    if (stat.isDirectory()) {
        files = collectFiles(resolvedPath);
    }
    else {
        files = [resolvedPath];
    }
    if (files.length === 0) {
        console.error("No scannable files found at the given path.");
        process.exit(1);
    }
    const allFindings = [];
    for (const filePath of files) {
        let content;
        try {
            content = fs.readFileSync(filePath, "utf-8");
        }
        catch {
            continue;
        }
        const lines = content.split("\n");
        const relPath = path.relative(resolvedPath, filePath) || path.basename(filePath);
        const ctx = {
            filePath: relPath,
            content,
            lines,
        };
        for (const scanner of index_js_1.ALL_SCANNERS) {
            allFindings.push(...scanner(ctx));
        }
    }
    const riskScore = (0, reporter_js_1.computeRiskScore)(allFindings);
    const level = riskScore === 0 ? "CLEAN"
        : riskScore <= 10 ? "LOW"
            : riskScore <= 40 ? "MEDIUM"
                : riskScore <= 100 ? "HIGH"
                    : "CRITICAL";
    return {
        targetPath: resolvedPath,
        scannedFiles: files.length,
        findings: allFindings,
        riskScore,
        riskLevel: level,
        summary: (0, reporter_js_1.generateSummary)(allFindings),
    };
}
// --- CLI ---
function printUsage() {
    console.log(`
skill-risk-auditor — Inspect OpenClaw skills for security risks

Usage:
  node audit.js <skill-path> [options]

Options:
  --json             Output results as JSON
  --compare <hash>   Compare local files against a published hash
  --help             Show this help message

Examples:
  node audit.js ./my-skill
  node audit.js ~/.claude/skills/some-skill --json
  node audit.js ./skill --compare abc123def456...
`);
}
function main() {
    const args = process.argv.slice(2);
    if (args.length === 0 || args.includes("--help")) {
        printUsage();
        process.exit(0);
    }
    let targetPath = "";
    let jsonOutput = false;
    let publishedHash = null;
    for (let i = 0; i < args.length; i++) {
        if (args[i] === "--json") {
            jsonOutput = true;
        }
        else if (args[i] === "--compare" && i + 1 < args.length) {
            publishedHash = args[++i];
        }
        else if (!args[i].startsWith("--")) {
            targetPath = args[i];
        }
    }
    if (!targetPath) {
        console.error("Error: no skill path provided.");
        printUsage();
        process.exit(1);
    }
    const result = auditSkill(targetPath);
    // Optional hash comparison
    let hashResult = null;
    if (publishedHash !== undefined) {
        const resolvedPath = path.resolve(targetPath);
        const stat = fs.statSync(resolvedPath);
        if (stat.isDirectory()) {
            hashResult = (0, hash_compare_js_1.compareHash)(resolvedPath, publishedHash);
        }
    }
    if (jsonOutput) {
        const output = { ...result };
        if (hashResult) {
            output.hashComparison = hashResult;
        }
        console.log(JSON.stringify(output, null, 2));
    }
    else {
        console.log((0, reporter_js_1.generateReport)(result));
        if (hashResult) {
            console.log("");
            console.log("  HASH COMPARISON");
            console.log("  " + "─".repeat(40));
            console.log(`  ${hashResult.details}`);
            console.log("");
        }
    }
    // Exit with non-zero if critical or high findings
    if (result.riskLevel === "CRITICAL" || result.riskLevel === "HIGH") {
        process.exit(2);
    }
}
main();
