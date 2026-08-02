#!/usr/bin/env node
/**
 * security-audit-mcp
 * MCP server for AI-powered security audits
 * Frameworks: OWASP Top 10, NIST SP 800-53, ISO 27001, PCI-DSS, SOC 2, HIPAA, CIS v8, GDPR
 * Author: Nasima Shaoz
 * License: MIT
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { FRAMEWORKS } from "./frameworks.js";
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup,
} from "./handlers.js";

export const server = new McpServer({
  name: "security-audit-mcp",
  version: "1.0.0",
  description: "AI-powered security audit tools for OWASP, NIST, ISO 27001 and more",
});

const frameworkKeys = Object.keys(FRAMEWORKS) as [string, ...string[]];
const searchFrameworkKeys = [...frameworkKeys, "all"] as [string, ...string[]];

// ─── Tool: list_frameworks ───────────────────────────────────────────────────
server.tool(
  "list_frameworks",
  "List all available security audit frameworks",
  {},
  handleListFrameworks
);

// ─── Tool: get_framework ─────────────────────────────────────────────────────
server.tool(
  "get_framework",
  "Get the full checklist for a specific security framework",
  {
    framework: z.enum(frameworkKeys).describe(
      `Framework ID: ${frameworkKeys.join(" | ")}`
    ),
  },
  handleGetFramework
);

// ─── Tool: audit_item ────────────────────────────────────────────────────────
server.tool(
  "audit_item",
  "Record a pass/fail/skip result for a specific audit control item",
  {
    sessionId: z.string().describe("Unique audit session ID (create any string)"),
    framework: z.enum(frameworkKeys),
    itemId: z.string().describe("Control ID e.g. A01, AC-2, A.5.1"),
    status: z.enum(["pass", "fail", "skip"]).describe("Audit result"),
    notes: z.string().optional().describe("Optional notes or remediation steps"),
  },
  handleAuditItem
);

// ─── Tool: generate_report ───────────────────────────────────────────────────
server.tool(
  "generate_report",
  "Generate a full audit report for a session",
  {
    sessionId: z.string(),
    format: z.enum(["json", "markdown", "html"]).default("markdown"),
  },
  handleGenerateReport
);

// ─── Tool: get_risk_summary ──────────────────────────────────────────────────
server.tool(
  "get_risk_summary",
  "Get a breakdown of risks by severity level for a framework",
  {
    framework: z.enum(frameworkKeys),
  },
  handleGetRiskSummary
);

// ─── Tool: search_controls ───────────────────────────────────────────────────
server.tool(
  "search_controls",
  "Search for security controls by keyword across all frameworks",
  {
    query: z.string().describe("Search term e.g. 'authentication', 'encryption', 'logging'"),
    framework: z.enum(searchFrameworkKeys).default("all"),
  },
  handleSearchControls
);

// ─── Tool: cve_lookup ────────────────────────────────────────────────────────
server.tool(
  "cve_lookup",
  "Lookup vulnerability details by CVE ID using MITRE API",
  {
    cveId: z.string().describe("CVE ID e.g., 'CVE-2021-44228'"),
  },
  handleCveLookup
);

// ─── Start Server ────────────────────────────────────────────────────────────
export async function main() {
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
