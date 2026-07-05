import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server, main } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock the StdioServerTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start = vi.fn();
      close = vi.fn();
    }
  };
});

describe("security-audit-mcp server", () => {
  let toolsMap: any;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2025-01-01T12:00:00.000Z"));

    // Access registered tools
    toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools || (server as any).tools;
    if (!toolsMap && (server as any).getRegisteredTools) {
      // In some sdk versions it might be in a different place, fallback iteration.
      // MCP Server SDK uses a Map for tools, but the memory hint says:
      // "The registry is an object, not a Map, so use bracket notation instead of .get()"
      // We will try standard access
    }
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should list frameworks", async () => {
    const listFrameworksTool = toolsMap["list_frameworks"];
    expect(listFrameworksTool).toBeDefined();

    const response = await listFrameworksTool.handler({});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);

    expect(data.frameworks).toBeInstanceOf(Array);
    expect(data.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === "pcidss")).toBe(true);
  });

  it("should get a specific framework", async () => {
    const getFrameworkTool = toolsMap["get_framework"];
    expect(getFrameworkTool).toBeDefined();

    const response = await getFrameworkTool.handler({ framework: "owasp" });
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);

    expect(data.name).toBe("OWASP Top 10");
    expect(data.items.length).toBeGreaterThan(0);
  });

  it("should return error for missing framework in get_framework", async () => {
    const getFrameworkTool = toolsMap["get_framework"];
    // Note: Zod validation usually catches this, but handler direct invocation bypasses it.
    // The handler does not explicitly check for missing fw in get_framework, it relies on Zod.
    // But let's check what happens if it's undefined.
    // Wait, the handler does: `if (!fw) return isError: true`
    const response = await getFrameworkTool.handler({ framework: "nonexistent" });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("should audit item and generate report", async () => {
    const auditItemTool = toolsMap["audit_item"];
    const sessionId = "test-session-123";

    // Audit an item
    const auditRes = await auditItemTool.handler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Test failure"
    });

    expect(auditRes.content[0].text).toContain("Test failure");

    // Update the same item
    await auditItemTool.handler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "Fixed"
    });

    // Audit an invalid item
    const invalidAuditRes = await auditItemTool.handler({
      sessionId,
      framework: "owasp",
      itemId: "INVALID",
      status: "fail",
    });
    expect(invalidAuditRes.isError).toBe(true);

    const generateReportTool = toolsMap["generate_report"];

    // JSON Report
    const jsonReport = await generateReportTool.handler({
      sessionId,
      format: "json"
    });
    const parsedJson = JSON.parse(jsonReport.content[0].text);
    expect(parsedJson.session).toBe(sessionId);
    expect(parsedJson.summary.passed).toBe(1);

    // Markdown Report
    const mdReport = await generateReportTool.handler({
      sessionId,
      format: "markdown"
    });
    expect(mdReport.content[0].text).toContain("## OWASP Top 10");
    expect(mdReport.content[0].text).toContain("Fixed");

    // HTML Report
    const htmlReport = await generateReportTool.handler({
      sessionId,
      format: "html"
    });
    expect(htmlReport.content[0].text).toContain("<!DOCTYPE html>");
  });

  it("should return error when generating report for missing session", async () => {
    const generateReportTool = toolsMap["generate_report"];
    const response = await generateReportTool.handler({
      sessionId: "missing",
      format: "json"
    });
    expect(response.isError).toBe(true);
  });

  it("should get risk summary", async () => {
    const getRiskSummaryTool = toolsMap["get_risk_summary"];
    const response = await getRiskSummaryTool.handler({ framework: "owasp" });
    const data = JSON.parse(response.content[0].text);

    expect(data.framework).toBe("OWASP Top 10");
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
    expect(data.riskBreakdown.HIGH).toBeDefined();
  });

  it("should search controls", async () => {
    const searchControlsTool = toolsMap["search_controls"];

    // Search all
    let response = await searchControlsTool.handler({ query: "encrypt", framework: "all" });
    let data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);

    // Search specific
    response = await searchControlsTool.handler({ query: "encrypt", framework: "owasp" });
    data = JSON.parse(response.content[0].text);
    expect(data.results["OWASP Top 10"]).toBeDefined();

    // Case insensitivity
    response = await searchControlsTool.handler({ query: "ENCRYPT", framework: "owasp" });
    data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
  });

  describe("cve_lookup tool", () => {
    it("should successfully lookup a CVE", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          cveMetadata: {
            state: "PUBLISHED",
            assignerShortName: "mitre",
            datePublished: "2021-12-10",
            dateUpdated: "2021-12-11"
          },
          containers: {
            cna: {
              descriptions: [{ value: "A test vulnerability" }],
              metrics: [{ cvssV3_1: { baseSeverity: "CRITICAL", baseScore: 10.0 } }]
            }
          }
        })
      });

      const cveLookupTool = toolsMap["cve_lookup"];
      const response = await cveLookupTool.handler({ cveId: "CVE-2021-44228" });
      const data = JSON.parse(response.content[0].text);

      expect(data.cveId).toBe("CVE-2021-44228");
      expect(data.severity).toBe("CRITICAL (10)");
      expect(data.description).toBe("A test vulnerability");
      expect(data.state).toBe("PUBLISHED");
    });

    it("should handle missing descriptions or metrics", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({})
      });

      const cveLookupTool = toolsMap["cve_lookup"];
      const response = await cveLookupTool.handler({ cveId: "CVE-2021-0001" });
      const data = JSON.parse(response.content[0].text);

      expect(data.severity).toBe("UNKNOWN");
      expect(data.description).toBe("No description available.");
    });

    it("should handle 404 not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      });

      const cveLookupTool = toolsMap["cve_lookup"];
      const response = await cveLookupTool.handler({ cveId: "CVE-UNKNOWN" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it("should handle general fetch errors", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

      const cveLookupTool = toolsMap["cve_lookup"];
      const response = await cveLookupTool.handler({ cveId: "CVE-ERROR" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Network Error");
    });
  });

  it("should run main without crashing", async () => {
     // Because we mocked StdioServerTransport, this just verifies it hooks up correctly
     await expect(main()).resolves.toBeUndefined();
  });
});
