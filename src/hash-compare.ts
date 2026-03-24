import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { HashComparison } from "./types.js";

/**
 * Computes a SHA-256 hash of all text files in a skill directory,
 * sorted by relative path for deterministic output.
 */
export function computeSkillHash(skillDir: string): string {
  const hash = crypto.createHash("sha256");
  const files = collectFiles(skillDir).sort();

  for (const file of files) {
    const relPath = path.relative(skillDir, file);
    const content = fs.readFileSync(file, "utf-8");
    hash.update(relPath + "\0" + content + "\0");
  }

  return hash.digest("hex");
}

function collectFiles(dir: string): string[] {
  const results: string[] = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    // Skip hidden dirs, node_modules, dist
    if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "dist") {
      continue;
    }

    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath));
    } else if (entry.isFile()) {
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
export function compareHash(skillDir: string, publishedHash: string | null): HashComparison {
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
