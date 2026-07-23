import { FRAMEWORKS } from "./frameworks.js";
import type { AuditSession, FrameworkItem } from "./types.js";

// In-memory session storage
export const sessions = new Map<string, AuditSession>();

export async function handleListFrameworks() {
  const list = Object.entries(FRAMEWORKS).map(([key, fw]) => ({
    id: key,
    name: fw.name,
    version: fw.version,
    itemCount: fw.items.length,
    description: fw.description,
  }));
  return {
    content: [{
      type: "text" as const,
      text: JSON.stringify({ frameworks: list }, null, 2),
    }],
  };
}

export async function handleGetFramework(args: { framework: string }) {
  const { framework } = args;
  const fw = FRAMEWORKS[framework];
  if (!fw) {
    return {
      content: [{ type: "text" as const, text: `Framework '${framework}' not found.` }],
      isError: true,
    };
  }
  return {
    content: [{
      type: "text" as const,
      text: JSON.stringify(fw, null, 2),
    }],
  };
}

export async function handleAuditItem(args: {
  sessionId: string;
  framework: string;
  itemId: string;
  status: "pass" | "fail" | "skip";
  notes?: string;
}) {
  const { sessionId, framework, itemId, status, notes } = args;
  const fw = FRAMEWORKS[framework];
  const item = fw?.items.find((i: FrameworkItem) => i.id === itemId);
  if (!item) {
    return {
      content: [{ type: "text" as const, text: `Item '${itemId}' not found in ${framework}.` }],
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
      type: "text" as const,
      text: JSON.stringify({
        recorded: result,
        sessionProgress: `${session.results.length} / ${fw.items.length} items audited`,
      }, null, 2),
    }],
  };
}

export async function handleGenerateReport(args: {
  sessionId: string;
  format: "json" | "markdown" | "html";
}) {
  const { sessionId, format } = args;
  const session = sessions.get(sessionId);
  if (!session) {
    return {
      content: [{ type: "text" as const, text: `Session '${sessionId}' not found.` }],
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
        type: "text" as const,
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

    return { content: [{ type: "text" as const, text: report }] };
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

  return { content: [{ type: "text" as const, text: html }] };
}

export async function handleGetRiskSummary(args: { framework: string }) {
  const { framework } = args;
  const fw = FRAMEWORKS[framework];
  const summary = { CRITICAL: [] as string[], HIGH: [] as string[], MEDIUM: [] as string[], LOW: [] as string[] };
  if (!fw) {
    return {
      content: [{ type: "text" as const, text: `Framework '${framework}' not found.` }],
      isError: true,
    };
  }
  fw.items.forEach((item: FrameworkItem) => {
    if (item.risk in summary) {
      summary[item.risk as keyof typeof summary].push(`${item.id}: ${item.title}`);
    }
  });
  return {
    content: [{
      type: "text" as const,
      text: JSON.stringify({ framework: fw.name, riskBreakdown: summary }, null, 2),
    }],
  };
}

export async function handleSearchControls(args: { query: string; framework: string }) {
  const { query, framework } = args;
  const q = query.toLowerCase();
  const results: Record<string, FrameworkItem[]> = {};

  const searchIn = framework === "all"
    ? Object.keys(FRAMEWORKS)
    : [framework];

  for (const fwKey of searchIn) {
    const fw = FRAMEWORKS[fwKey];
    if (!fw) continue;
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
      type: "text" as const,
      text: JSON.stringify({ query, totalMatches: total, results }, null, 2),
    }],
  };
}

export async function handleCveLookup(args: { cveId: string }) {
  const { cveId } = args;
  try {
    const url = `https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`;
    const response = await fetch(url);
    if (!response.ok) {
      return {
        content: [{ type: "text" as const, text: `CVE '${cveId}' not found or API error.` }],
        isError: true,
      };
    }
    const data = await response.json();
    return {
      content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
    };
  } catch (err: any) {
    return {
      content: [{ type: "text" as const, text: `Failed to lookup CVE: ${err.message}` }],
      isError: true,
    };
  }
}
