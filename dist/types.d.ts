export interface FrameworkItem {
    id: string;
    title: string;
    description: string;
    risk: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}
export interface Framework {
    name: string;
    version: string;
    description: string;
    items: FrameworkItem[];
}
export interface AuditResult {
    itemId: string;
    title: string;
    risk: string;
    status: "pass" | "fail" | "skip";
    notes: string;
}
export interface AuditSession {
    id: string;
    framework: string;
    results: AuditResult[];
    startedAt: string;
}
//# sourceMappingURL=types.d.ts.map