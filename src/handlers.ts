import { FRAMEWORKS } from "./frameworks.js";
import { getSession, setSession } from "./state.js";
import type { FrameworkItem } from "./types.js";

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
  const fw = FRAMEWORKS[args.framework];
  if (!fw) {
    return {
      content: [{ type: "text" as const, text: `Framework '${args.framework}' not found.` }],
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

export async function handleAuditItem(args: { sessionId: string; framework: string; itemId: string; status: "pass" | "fail" | "skip"; notes?: string }) {
  const fw = FRAMEWORKS[args.framework];
  if (!fw) {
    return {
      content: [{ type: "text" as const, text: `Framework '${args.framework}' not found.` }],
      isError: true,
    };
  }

  const item = fw.items.find((i: FrameworkItem) => i.id === args.itemId);
  if (!item) {
    return {
      content: [{ type: "text" as const, text: `Item '${args.itemId}' not found in ${args.framework}.` }],
      isError: true,
    };
  }

  let session = getSession(args.sessionId);
  if (!session) {
    session = { id: args.sessionId, framework: args.framework, results: [], startedAt: new Date().toISOString() };
    setSession(args.sessionId, session);
  }

  // Update or add result
  const existing = session.results.findIndex(r => r.itemId === args.itemId);
  const result = { itemId: args.itemId, title: item.title, risk: item.risk, status: args.status, notes: args.notes ?? "" };
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

export async function handleGenerateReport(args: { sessionId: string; format?: "json" | "markdown" | "html" }) {
  const format = args.format || "markdown";
  const session = getSession(args.sessionId);
  if (!session) {
    return {
      content: [{ type: "text" as const, text: `Session '${args.sessionId}' not found.` }],
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
          session: args.sessionId,
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
  const fw = FRAMEWORKS[args.framework];
  if (!fw) {
    return {
      content: [{ type: "text" as const, text: `Framework '${args.framework}' not found.` }],
      isError: true,
    };
  }

  const summary = { CRITICAL: [] as string[], HIGH: [] as string[], MEDIUM: [] as string[], LOW: [] as string[] };
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

export async function handleSearchControls(args: { query: string; framework?: string }) {
  const q = args.query.toLowerCase();
  const results: Record<string, FrameworkItem[]> = {};

  const searchIn = args.framework === "all" || !args.framework
    ? Object.keys(FRAMEWORKS)
    : [args.framework];

  for (const fwKey of searchIn) {
    const fw = FRAMEWORKS[fwKey];
    if (fw) {
      const matches = fw.items.filter((item: FrameworkItem) =>
        item.id.toLowerCase().includes(q) ||
        item.title.toLowerCase().includes(q) ||
        item.description.toLowerCase().includes(q)
      );
      if (matches.length > 0) {
        results[fw.name] = matches;
      }
    }
  }

  const total = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
  return {
    content: [{
      type: "text" as const,
      text: JSON.stringify({ query: args.query, totalMatches: total, results }, null, 2),
    }],
  };
}

export async function handleCveLookup(args: { cveId: string }) {
  try {
    const response = await fetch(`https://cveawg.mitre.org/api/cve/${encodeURIComponent(args.cveId)}`);
    if (!response.ok) {
       if (response.status === 404) {
          return {
            content: [{ type: "text" as const, text: `CVE '${args.cveId}' not found.` }],
            isError: true,
          };
       }
       throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify(data, null, 2),
      }],
    };
  } catch (error) {
    return {
      content: [{ type: "text" as const, text: `Error fetching CVE data: ${error instanceof Error ? error.message : String(error)}` }],
      isError: true,
    };
  }
}
