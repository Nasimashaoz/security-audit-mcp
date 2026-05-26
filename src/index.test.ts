import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "./index.js";

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start = vi.fn();
      close = vi.fn();
    },
  };
});

describe("security-audit-mcp Tools", () => {
  let tools: Record<string, any> = {};

  beforeEach(() => {
    // Access the registered tools from the MCP server instance
    const registeredTools = (server as any)._registeredTools || (server as any).tools;
    if (registeredTools instanceof Map) {
      tools = Object.fromEntries(registeredTools.entries());
    } else if (Array.isArray(registeredTools)) {
      tools = registeredTools.reduce((acc, t) => {
        acc[t.name] = t;
        return acc;
      }, {});
    } else {
      tools = registeredTools;
    }

    global.fetch = vi.fn();
  });

  it("should have all tools registered", () => {
    expect(tools.list_frameworks).toBeDefined();
    expect(tools.get_framework).toBeDefined();
    expect(tools.audit_item).toBeDefined();
    expect(tools.generate_report).toBeDefined();
    expect(tools.get_risk_summary).toBeDefined();
    expect(tools.search_controls).toBeDefined();
    expect(tools.cve_lookup).toBeDefined();
  });

  it("list_frameworks should return frameworks", async () => {
    const handler = tools.list_frameworks.handler || tools.list_frameworks;
    const result = await handler({});
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.find((f: any) => f.id === "owasp")).toBeDefined();
    expect(data.frameworks.find((f: any) => f.id === "pcidss")).toBeDefined();
  });

  it("get_framework should return a specific framework", async () => {
    const handler = tools.get_framework.handler || tools.get_framework;
    const result = await handler({ framework: "nist" });
    const data = JSON.parse(result.content[0].text);
    expect(data.name).toContain("NIST");
  });

  it("get_framework should error on invalid framework", async () => {
    const handler = tools.get_framework.handler || tools.get_framework;
    const result = await handler({ framework: "invalid" });
    expect(result.isError).toBe(true);
  });

  it("audit_item should record an item and generate_report should output it", async () => {
    const sessionId = "test-session-1";

    // Audit an item
    const auditHandler = tools.audit_item.handler || tools.audit_item;
    const auditRes = await auditHandler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Test notes"
    });

    const auditData = JSON.parse(auditRes.content[0].text);
    expect(auditData.recorded.status).toBe("fail");

    // Generate a report in JSON
    const reportHandler = tools.generate_report.handler || tools.generate_report;
    const reportRes = await reportHandler({ sessionId, format: "json" });
    const reportData = JSON.parse(reportRes.content[0].text);
    expect(reportData.allResults.length).toBe(1);
    expect(reportData.allResults[0].itemId).toBe("A01");
  });

  it("get_risk_summary should return summary", async () => {
    const handler = tools.get_risk_summary.handler || tools.get_risk_summary;
    const result = await handler({ framework: "owasp" });
    const data = JSON.parse(result.content[0].text);
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
  });

  it("search_controls should find controls", async () => {
    const handler = tools.search_controls.handler || tools.search_controls;
    const result = await handler({ query: "authentication", framework: "all" });
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
  });

  it("cve_lookup should fetch CVE data successfully", async () => {
    const mockData = { id: "CVE-2021-44228", description: "Log4Shell" };
    (global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockData
    });

    const handler = tools.cve_lookup.handler || tools.cve_lookup;
    const result = await handler({ cveId: "CVE-2021-44228" });
    const data = JSON.parse(result.content[0].text);
    expect(data.id).toBe("CVE-2021-44228");
    expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
  });

  it("cve_lookup should handle errors gracefully", async () => {
    (global.fetch as any).mockResolvedValue({
      ok: false,
      status: 404
    });

    const handler = tools.cve_lookup.handler || tools.cve_lookup;
    const result = await handler({ cveId: "CVE-UNKNOWN" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });
});
