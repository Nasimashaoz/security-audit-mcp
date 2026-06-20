import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server, main } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport to prevent actual connection attempts
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      constructor() {}
      start() {}
      close() {}
    },
  };
});

describe("security-audit-mcp server tools", () => {
  let toolsMap: any;

  beforeEach(() => {
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T12:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should list all frameworks", async () => {
    const listFrameworksTool = toolsMap["list_frameworks"];
    expect(listFrameworksTool).toBeDefined();

    const response = await listFrameworksTool.handler({});
    expect(response.content).toBeDefined();
    expect(response.content[0].type).toBe("text");

    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.frameworks).toBeDefined();
    expect(parsed.frameworks.length).toBeGreaterThan(0);
    expect(parsed.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
    expect(parsed.frameworks.some((f: any) => f.id === "cis")).toBe(true);
  });

  it("should get specific framework", async () => {
    const getFrameworkTool = toolsMap["get_framework"];
    expect(getFrameworkTool).toBeDefined();

    const response = await getFrameworkTool.handler({ framework: "owasp" });
    expect(response.content).toBeDefined();
    expect(response.content[0].type).toBe("text");
    expect(response.isError).toBeUndefined();

    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.name).toBe("OWASP Top 10");
  });

  it("should return error for invalid framework in get_framework", async () => {
    const getFrameworkTool = toolsMap["get_framework"];
    const response = await getFrameworkTool.handler({ framework: "nonexistent" });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("should record an audit item and track session", async () => {
    const auditItemTool = toolsMap["audit_item"];
    expect(auditItemTool).toBeDefined();

    const sessionId = "test-session-1";
    const response1 = await auditItemTool.handler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "LGTM",
    });

    expect(response1.content).toBeDefined();
    expect(response1.isError).toBeUndefined();
    const parsed1 = JSON.parse(response1.content[0].text);
    expect(parsed1.recorded.status).toBe("pass");
    expect(parsed1.recorded.notes).toBe("LGTM");
    expect(parsed1.sessionProgress).toContain("1 /");

    // Overwrite the same item
    const response2 = await auditItemTool.handler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Found a bug",
    });

    const parsed2 = JSON.parse(response2.content[0].text);
    expect(parsed2.recorded.status).toBe("fail");
    expect(parsed2.recorded.notes).toBe("Found a bug");
  });

  it("should generate report for an existing session", async () => {
    const auditItemTool = toolsMap["audit_item"];
    const generateReportTool = toolsMap["generate_report"];

    const sessionId = "test-session-2";
    await auditItemTool.handler({ sessionId, framework: "owasp", itemId: "A01", status: "pass" });
    await auditItemTool.handler({ sessionId, framework: "owasp", itemId: "A02", status: "fail" });
    await auditItemTool.handler({ sessionId, framework: "owasp", itemId: "A03", status: "skip" });

    // JSON format
    const responseJson = await generateReportTool.handler({ sessionId, format: "json" });
    const parsedJson = JSON.parse(responseJson.content[0].text);
    expect(parsedJson.summary.passed).toBe(1);
    expect(parsedJson.summary.failed).toBe(1);
    expect(parsedJson.summary.skipped).toBe(1);
    expect(parsedJson.score).toBe("33%");

    // Markdown format
    const responseMd = await generateReportTool.handler({ sessionId, format: "markdown" });
    expect(responseMd.content[0].text).toContain("33%");
    expect(responseMd.content[0].text).toContain("A01");

    // HTML format
    const responseHtml = await generateReportTool.handler({ sessionId, format: "html" });
    expect(responseHtml.content[0].text).toContain("<!DOCTYPE html>");
    expect(responseHtml.content[0].text).toContain("33%");
  });

  it("should get risk summary", async () => {
    const getRiskSummaryTool = toolsMap["get_risk_summary"];
    const response = await getRiskSummaryTool.handler({ framework: "owasp" });

    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.riskBreakdown).toBeDefined();
    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
    expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("should search controls across all frameworks", async () => {
    const searchControlsTool = toolsMap["search_controls"];
    const response = await searchControlsTool.handler({ query: "injection", framework: "all" });

    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(parsed.results["OWASP Top 10"]).toBeDefined();
    expect(parsed.results["OWASP Top 10"].some((i: any) => i.id === "A03")).toBe(true);
  });

  it("should search controls across a single framework", async () => {
    const searchControlsTool = toolsMap["search_controls"];
    const response = await searchControlsTool.handler({ query: "injection", framework: "owasp" });

    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(parsed.results["OWASP Top 10"]).toBeDefined();
    expect(parsed.results["NIST SP 800-53"]).toBeUndefined();
  });

  describe("cve_lookup tool", () => {
    it("should fetch CVE details successfully", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ cveMetadata: { cveId: "CVE-2021-44228" } }),
      });

      const cveLookupTool = toolsMap["cve_lookup"];
      const response = await cveLookupTool.handler({ cveId: "CVE-2021-44228" });

      expect(response.isError).toBeUndefined();
      const parsed = JSON.parse(response.content[0].text);
      expect(parsed.cveMetadata.cveId).toBe("CVE-2021-44228");
    });

    it("should handle 404 not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      const cveLookupTool = toolsMap["cve_lookup"];
      const response = await cveLookupTool.handler({ cveId: "CVE-1234-5678" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it("should handle network errors", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network failure"));

      const cveLookupTool = toolsMap["cve_lookup"];
      const response = await cveLookupTool.handler({ cveId: "CVE-2021-44228" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error fetching CVE details");
    });
  });

  it("should execute main() without error", async () => {
    // Suppress console.error for the test
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    // server.connect uses transport, which we mocked
    await main();

    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("security-audit-mcp server running"));
    consoleSpy.mockRestore();
  });
});
