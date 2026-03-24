import { AuditResult, Finding } from "./types.js";
export declare function computeRiskScore(findings: Finding[]): number;
export declare function generateReport(result: AuditResult): string;
export declare function generateSummary(findings: Finding[]): string;
