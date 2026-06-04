import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start = vi.fn();
      close = vi.fn();
    }
  };
});

describe("MCP Server Tools", () => {
  let toolsMap: Record<string, any>;

  beforeEach(() => {
    // Access internal registered tools
    toolsMap = (server as any)._registeredTools || {};
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should have all required tools registered", () => {
    expect(toolsMap).toHaveProperty("list_frameworks");
    expect(toolsMap).toHaveProperty("get_framework");
    expect(toolsMap).toHaveProperty("audit_item");
    expect(toolsMap).toHaveProperty("generate_report");
    expect(toolsMap).toHaveProperty("get_risk_summary");
    expect(toolsMap).toHaveProperty("search_controls");
    expect(toolsMap).toHaveProperty("cve_lookup");
  });

  it("list_frameworks should return all frameworks", async () => {
    const handler = toolsMap["list_frameworks"].handler;
    const result = await handler({});
    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe("text");

    const data = JSON.parse(result.content[0].text);
    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.length).toBeGreaterThan(0);
    expect(data.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === "pcidss")).toBe(true);
  });

  it("get_framework should return a specific framework", async () => {
    const handler = toolsMap["get_framework"].handler;
    const result = await handler({ framework: "owasp" });

    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
    expect(data.items.length).toBeGreaterThan(0);
  });

  it("get_framework should handle missing framework", async () => {
    const handler = toolsMap["get_framework"].handler;
    const result = await handler({ framework: "nonexistent" });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("audit_item should record results and allow updates", async () => {
    const handler = toolsMap["audit_item"].handler;
    const sessionId = "test-session-1";

    // First recording
    const result1 = await handler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Test failure"
    });

    expect(result1.content[0].text).toContain("Test failure");

    // Update recording
    const result2 = await handler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "Fixed"
    });

    expect(result2.content[0].text).toContain("Fixed");
    expect(result2.content[0].text).toContain("1 /"); // Still 1 item audited
  });

  it("audit_item should return error for invalid item", async () => {
    const handler = toolsMap["audit_item"].handler;
    const result = await handler({
      sessionId: "test-session-invalid",
      framework: "owasp",
      itemId: "INVALID-ITEM",
      status: "pass"
    });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("generate_report should handle missing session", async () => {
    const handler = toolsMap["generate_report"].handler;
    const result = await handler({ sessionId: "nonexistent-session" });

    expect(result.isError).toBe(true);
  });

  it("generate_report should generate reports in different formats", async () => {
    // Setup a session first
    const auditHandler = toolsMap["audit_item"].handler;
    const sessionId = "report-session-1";

    await auditHandler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Critical failure"
    });
    await auditHandler({
      sessionId,
      framework: "owasp",
      itemId: "A02",
      status: "pass"
    });

    const reportHandler = toolsMap["generate_report"].handler;

    // Test JSON
    const jsonResult = await reportHandler({ sessionId, format: "json" });
    const jsonData = JSON.parse(jsonResult.content[0].text);
    expect(jsonData.summary.failed).toBe(1);
    expect(jsonData.summary.passed).toBe(1);
    expect(jsonData.score).toBe("50%");

    // Test Markdown
    const mdResult = await reportHandler({ sessionId, format: "markdown" });
    expect(mdResult.content[0].text).toContain("Critical Findings");
    expect(mdResult.content[0].text).toContain("| A01 |");

    // Test HTML
    const htmlResult = await reportHandler({ sessionId, format: "html" });
    expect(htmlResult.content[0].text).toContain("<!DOCTYPE html>");
    expect(htmlResult.content[0].text).toContain("50%");
  });

  it("get_risk_summary should return risk breakdown", async () => {
    const handler = toolsMap["get_risk_summary"].handler;
    const result = await handler({ framework: "owasp" });

    const data = JSON.parse(result.content[0].text);
    expect(data.framework).toBe("OWASP Top 10");
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
  });

  it("search_controls should find controls by keyword", async () => {
    const handler = toolsMap["search_controls"].handler;
    const result = await handler({ query: "encrypt", framework: "all" });

    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    // Encryption is mentioned in OWASP A02 and NIST SC-28 at least
    expect(Object.keys(data.results).length).toBeGreaterThan(0);
  });

  it("search_controls should filter by framework", async () => {
    const handler = toolsMap["search_controls"].handler;
    const result = await handler({ query: "access", framework: "owasp" });

    const data = JSON.parse(result.content[0].text);
    expect(Object.keys(data.results)).toEqual(["OWASP Top 10"]);
  });

  describe("cve_lookup tool", () => {
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
      originalFetch = global.fetch;
      global.fetch = vi.fn();
    });

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it("should fetch and format CVE details correctly", async () => {
      const mockCveData = {
        cveMetadata: {
          cveId: "CVE-2021-44228",
          state: "PUBLISHED",
          datePublished: "2021-12-10T10:00:00.000Z"
        },
        containers: {
          cna: {
            descriptions: [{ value: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints." }],
            metrics: [{
              cvssV3_1: {
                baseScore: 10.0,
                baseSeverity: "CRITICAL",
                vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
              }
            }],
            affected: [{
              vendor: "Apache",
              product: "Log4j",
              versions: [{ version: "2.0-beta9", status: "affected" }, { version: "2.14.1", status: "affected" }]
            }]
          }
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");

      const data = JSON.parse(result.content[0].text);
      expect(data.cveId).toBe("CVE-2021-44228");
      expect(data.state).toBe("PUBLISHED");
      expect(data.description).toContain("Apache Log4j2");
      expect(data.cvss.score).toBe(10.0);
      expect(data.cvss.severity).toBe("CRITICAL");
      expect(data.affectedProducts[0].vendor).toBe("Apache");
      expect(data.affectedProducts[0].versions.length).toBe(2);
    });

    it("should return error when CVE is not found", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-INVALID" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle general fetch errors gracefully", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network connection failed"));

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch CVE data");
      expect(result.content[0].text).toContain("Network connection failed");
    });
  });
});
