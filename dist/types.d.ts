export type Severity = "critical" | "high" | "medium" | "low" | "info";
export interface Finding {
    scanner: string;
    severity: Severity;
    file: string;
    line: number;
    matched: string;
    description: string;
}
export interface ScanContext {
    filePath: string;
    content: string;
    lines: string[];
}
export type Scanner = (ctx: ScanContext) => Finding[];
export interface AuditResult {
    targetPath: string;
    scannedFiles: number;
    findings: Finding[];
    riskScore: number;
    riskLevel: string;
    summary: string;
}
export interface HashComparison {
    localHash: string;
    publishedHash: string | null;
    match: boolean | null;
    details: string;
}
