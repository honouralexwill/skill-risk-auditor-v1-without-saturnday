import { HashComparison } from "./types.js";
/**
 * Computes a SHA-256 hash of all text files in a skill directory,
 * sorted by relative path for deterministic output.
 */
export declare function computeSkillHash(skillDir: string): string;
/**
 * Compare local skill hash against a provided published hash.
 * The published hash should come from a registry or the user.
 */
export declare function compareHash(skillDir: string, publishedHash: string | null): HashComparison;
