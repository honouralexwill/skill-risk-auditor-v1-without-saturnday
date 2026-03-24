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
exports.computeSkillHash = computeSkillHash;
exports.compareHash = compareHash;
const crypto = __importStar(require("node:crypto"));
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
/**
 * Computes a SHA-256 hash of all text files in a skill directory,
 * sorted by relative path for deterministic output.
 */
function computeSkillHash(skillDir) {
    const hash = crypto.createHash("sha256");
    const files = collectFiles(skillDir).sort();
    for (const file of files) {
        const relPath = path.relative(skillDir, file);
        const content = fs.readFileSync(file, "utf-8");
        hash.update(relPath + "\0" + content + "\0");
    }
    return hash.digest("hex");
}
function collectFiles(dir) {
    const results = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        // Skip hidden dirs, node_modules, dist
        if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "dist") {
            continue;
        }
        if (entry.isDirectory()) {
            results.push(...collectFiles(fullPath));
        }
        else if (entry.isFile()) {
            // Only hash text files
            const ext = path.extname(entry.name).toLowerCase();
            const textExts = new Set([
                ".md", ".ts", ".js", ".json", ".yaml", ".yml",
                ".sh", ".bash", ".zsh", ".py", ".rb", ".go",
                ".rs", ".toml", ".txt", ".cfg", ".ini", ".env",
                ".html", ".css", ".xml", ".csv",
            ]);
            if (textExts.has(ext) || entry.name === "SKILL.md" || entry.name === "Makefile") {
                results.push(fullPath);
            }
        }
    }
    return results;
}
/**
 * Compare local skill hash against a provided published hash.
 * The published hash should come from a registry or the user.
 */
function compareHash(skillDir, publishedHash) {
    const localHash = computeSkillHash(skillDir);
    if (!publishedHash) {
        return {
            localHash,
            publishedHash: null,
            match: null,
            details: `Local hash: ${localHash}. No published hash provided for comparison.`,
        };
    }
    const match = localHash === publishedHash;
    return {
        localHash,
        publishedHash,
        match,
        details: match
            ? `Hashes match (${localHash.substring(0, 16)}…). The local copy matches the published version.`
            : `MISMATCH! Local: ${localHash.substring(0, 16)}… vs Published: ${publishedHash.substring(0, 16)}…. The local files have been modified or differ from the published version.`,
    };
}
