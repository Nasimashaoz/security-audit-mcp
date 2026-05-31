#!/usr/bin/env node
/**
 * security-audit-mcp
 * MCP server for AI-powered security audits
 * Frameworks: OWASP Top 10, NIST SP 800-53, ISO 27001
 * Author: Nasima Shaoz
 * License: MIT
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { FRAMEWORKS } from "./frameworks.js";
import type { AuditSession, FrameworkItem } from "./types.js";

export const server = new McpServer({
  name: "security-audit-mcp",
  version: "1.0.0",
  description: "AI-powered security audit tools for OWASP, NIST, and ISO 27001",
});

// In-memory session storage
const sessions = new Map<string, AuditSession>();

// ─── Tool: list_frameworks ───────────────────────────────────────────────────
server.tool(
  "list_frameworks",
  "List all available security audit frameworks",
  {},
  async () => {
    const list = Object.entries(FRAMEWORKS).map(([key, fw]) => ({
      id: key,
      name: fw.name,
      version: fw.version,
      itemCount: fw.items.length,
      description: fw.description,
    }));
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ frameworks: list }, null, 2),
      }],
    };
  }
);

// ─── Tool: get_framework ─────────────────────────────────────────────────────
server.tool(
  "get_framework",
  "Get the full checklist for a specific security framework",
  {
    framework: z.enum(Object.keys(FRAMEWORKS) as [string, ...string[]]).describe(
      "Framework ID: owasp | nist | iso27001"
    ),
  },
  async ({ framework }) => {
    const fw = FRAMEWORKS[framework];
    if (!fw) {
      return {
        content: [{ type: "text", text: `Framework '${framework}' not found.` }],
        isError: true,
      };
    }
    return {
      content: [{
        type: "text",
        text: JSON.stringify(fw, null, 2),
      }],
    };
  }
);

// ─── Tool: audit_item ────────────────────────────────────────────────────────
server.tool(
  "audit_item",
  "Record a pass/fail/skip result for a specific audit control item",
  {
    sessionId: z.string().describe("Unique audit session ID (create any string)"),
    framework: z.enum(Object.keys(FRAMEWORKS) as [string, ...string[]]),
    itemId: z.string().describe("Control ID e.g. A01, AC-2, A.5.1"),
    status: z.enum(["pass", "fail", "skip"]).describe("Audit result"),
    notes: z.string().optional().describe("Optional notes or remediation steps"),
  },
  async ({ sessionId, framework, itemId, status, notes }) => {
    const fw = FRAMEWORKS[framework];
    const item = fw?.items.find((i: FrameworkItem) => i.id === itemId);
    if (!item) {
      return {
        content: [{ type: "text", text: `Item '${itemId}' not found in ${framework}.` }],
        isError: true,
      };
    }

    if (!sessions.has(sessionId)) {
      sessions.set(sessionId, { id: sessionId, framework, results: [], startedAt: new Date().toISOString() });
    }
    const session = sessions.get(sessionId)!;

    // Update or add result
    const existing = session.results.findIndex(r => r.itemId === itemId);
    const result = { itemId, title: item.title, risk: item.risk, status, notes: notes ?? "" };
    if (existing >= 0) {
      session.results[existing] = result;
    } else {
      session.results.push(result);
    }

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          recorded: result,
          sessionProgress: `${session.results.length} / ${fw.items.length} items audited`,
        }, null, 2),
      }],
    };
  }
);

// ─── Tool: generate_report ───────────────────────────────────────────────────
server.tool(
  "generate_report",
  "Generate a full audit report for a session",
  {
    sessionId: z.string(),
    format: z.enum(["json", "markdown", "html"]).default("markdown"),
  },
  async ({ sessionId, format }) => {
    const session = sessions.get(sessionId);
    if (!session) {
      return {
        content: [{ type: "text", text: `Session '${sessionId}' not found.` }],
        isError: true,
      };
    }

    const fw = FRAMEWORKS[session.framework];
    const passed = session.results.filter(r => r.status === "pass").length;
    const failed = session.results.filter(r => r.status === "fail").length;
    const skipped = session.results.filter(r => r.status === "skip").length;
    const score = session.results.length > 0
      ? Math.round((passed / session.results.length) * 100)
      : 0;

    const criticalFails = session.results.filter(r => r.status === "fail" && r.risk === "CRITICAL");
    const highFails = session.results.filter(r => r.status === "fail" && r.risk === "HIGH");

    if (format === "json") {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            session: sessionId,
            framework: fw.name,
            score: `${score}%`,
            summary: { passed, failed, skipped },
            criticalFindings: criticalFails,
            highFindings: highFails,
            allResults: session.results,
            generatedAt: new Date().toISOString(),
          }, null, 2),
        }],
      };
    }

    if (format === "markdown") {
      const rows = session.results.map(r =>
        `| ${r.itemId} | ${r.title} | ${r.risk} | ${r.status.toUpperCase()} | ${r.notes} |`
      ).join("\n");

      const criticalSection = criticalFails.length > 0
        ? `\n## 🚨 Critical Findings\n${criticalFails.map(r => `- **${r.itemId}** ${r.title}${r.notes ? `: ${r.notes}` : ""}`).join("\n")}`
        : "";

      const report = `# 🔒 Security Audit Report\n
## ${fw.name} (${fw.version})\n
**Score:** ${score}% | **Passed:** ${passed} | **Failed:** ${failed} | **Skipped:** ${skipped}  \n**Generated:** ${new Date().toISOString()}\n${criticalSection}\n
## Results\n
| ID | Title | Risk | Status | Notes |\n|---|---|---|---|---|\n${rows}\n`;

      return { content: [{ type: "text", text: report }] };
    }

    // HTML format
    const rows = session.results.map(r => {
      const color = r.status === "pass" ? "#16a34a" : r.status === "fail" ? "#dc2626" : "#6b7280";
      return `<tr><td>${r.itemId}</td><td>${r.title}</td><td>${r.risk}</td><td style="color:${color};font-weight:bold">${r.status.toUpperCase()}</td><td>${r.notes}</td></tr>`;
    }).join("");

    const html = `<!DOCTYPE html><html><head><title>Security Audit Report</title>
<style>body{font-family:system-ui;margin:40px;color:#111}h1{color:#dc2626}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #e5e7eb;padding:10px;text-align:left}th{background:#f9fafb;font-weight:600}.score{font-size:2em;font-weight:bold;color:#16a34a}</style></head>
<body><h1>🔒 Security Audit Report</h1><h2>${fw.name}</h2><div class="score">${score}%</div><p>Passed: ${passed} | Failed: ${failed} | Skipped: ${skipped}</p>
<table><tr><th>ID</th><th>Title</th><th>Risk</th><th>Status</th><th>Notes</th></tr>${rows}</table>
<p><small>Generated ${new Date().toISOString()} by security-audit-mcp</small></p></body></html>`;

    return { content: [{ type: "text", text: html }] };
  }
);

// ─── Tool: get_risk_summary ──────────────────────────────────────────────────
server.tool(
  "get_risk_summary",
  "Get a breakdown of risks by severity level for a framework",
  {
    framework: z.enum(Object.keys(FRAMEWORKS) as [string, ...string[]]),
  },
  async ({ framework }) => {
    const fw = FRAMEWORKS[framework];
    const summary = { CRITICAL: [] as string[], HIGH: [] as string[], MEDIUM: [] as string[], LOW: [] as string[] };
    fw.items.forEach((item: FrameworkItem) => {
      if (item.risk in summary) {
        summary[item.risk as keyof typeof summary].push(`${item.id}: ${item.title}`);
      }
    });
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ framework: fw.name, riskBreakdown: summary }, null, 2),
      }],
    };
  }
);

// ─── Tool: search_controls ───────────────────────────────────────────────────
server.tool(
  "search_controls",
  "Search for security controls by keyword across all frameworks",
  {
    query: z.string().describe("Search term e.g. 'authentication', 'encryption', 'logging'"),
    framework: z.enum([...Object.keys(FRAMEWORKS), "all"] as unknown as [string, ...string[]]).default("all"),
  },
  async ({ query, framework }) => {
    const q = query.toLowerCase();
    const results: Record<string, FrameworkItem[]> = {};

    const searchIn = framework === "all"
      ? Object.keys(FRAMEWORKS)
      : [framework];

    for (const fwKey of searchIn) {
      const fw = FRAMEWORKS[fwKey];
      const matches = fw.items.filter((item: FrameworkItem) =>
        item.id.toLowerCase().includes(q) ||
        item.title.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q)
      );
      if (matches.length > 0) {
        results[fw.name] = matches;
      }
    }

    const total = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ query, totalMatches: total, results }, null, 2),
      }],
    };
  }
);


// ─── Tool: cve_lookup ────────────────────────────────────────────────────────
server.tool(
  "cve_lookup",
  "Look up details for a specific Common Vulnerabilities and Exposures (CVE) identifier",
  {
    cveId: z.string().describe("The CVE ID to look up, e.g. 'CVE-2021-44228'"),
  },
  async ({ cveId }) => {
    try {
      const response = await fetch(`https://cveawg.mitre.org/api/cve/${cveId}`);
      if (!response.ok) {
        if (response.status === 404) {
             return {
                content: [{ type: "text", text: `CVE '${cveId}' not found.` }],
                isError: true,
             };
        }
        throw new Error(`API request failed with status ${response.status}`);
      }

      const data = await response.json();
      return {
        content: [{
          type: "text",
          text: JSON.stringify(data, null, 2),
        }],
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error fetching CVE details: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }
);

// ─── Start Server ────────────────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("🔐 security-audit-mcp server running on stdio");
}

if (process.env.NODE_ENV !== "test") {
  main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
}
