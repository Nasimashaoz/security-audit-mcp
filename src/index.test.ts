import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock global fetch for cve_lookup tool
global.fetch = vi.fn();

// Mock StdioServerTransport since real stdio cannot be connected in tests
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        // Add minimal required interface properties to satisfy McpServer
        // Though we test tools via `_registeredTools` directly.
      };
    }),
  };
});

describe("security-audit-mcp server tools", () => {
  let tools: any;

  beforeEach(() => {
    // Access registered tools in MCP server
    tools = (server as any)._registeredTools;
  });

  it("should have all required tools registered", () => {
    expect(tools["list_frameworks"]).toBeDefined();
    expect(tools["get_framework"]).toBeDefined();
    expect(tools["audit_item"]).toBeDefined();
    expect(tools["generate_report"]).toBeDefined();
    expect(tools["get_risk_summary"]).toBeDefined();
    expect(tools["search_controls"]).toBeDefined();
    expect(tools["cve_lookup"]).toBeDefined();
  });

  describe("list_frameworks", () => {
    it("should return the list of frameworks", async () => {
      const handler = tools["list_frameworks"].handler;
      const result = await handler({});
      expect(result).toBeDefined();
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    });
  });

  describe("get_framework", () => {
    it("should return framework details for a valid framework", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "owasp" }, {});
      expect(result.isError).toBeUndefined();
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
    });

    it("should handle an invalid framework gracefully", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "invalid_framework" }, {});
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item", () => {
    it("should record an audit result", async () => {
      const handler = tools["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      }, {});
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");
    });

    it("should fail when itemId does not exist in framework", async () => {
      const handler = tools["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "NONEXISTENT",
        status: "pass"
      }, {});
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("generate_report", () => {
    beforeEach(async () => {
      // Seed a session first
      const auditHandler = tools["audit_item"].handler;
      await auditHandler({
        sessionId: "report-session",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Test"
      }, {});
    });

    it("should generate a json report", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "json" }, {});
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe("report-session");
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.summary.passed).toBe(1);
    });

    it("should return an error for non-existent session", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "missing-session", format: "json" }, {});
      expect(result.isError).toBe(true);
    });
  });

  describe("get_risk_summary", () => {
    it("should return risk summary", async () => {
      const handler = tools["get_risk_summary"].handler;
      const result = await handler({ framework: "owasp" }, {});
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(data.riskBreakdown.HIGH).toBeDefined();
    });
  });

  describe("search_controls", () => {
    it("should find controls across all frameworks", async () => {
      const handler = tools["search_controls"].handler;
      const result = await handler({ query: "authentication", framework: "all" }, {});
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
    });

    it("should find controls in a specific framework", async () => {
      const handler = tools["search_controls"].handler;
      const result = await handler({ query: "access", framework: "owasp" }, {});
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });
  });

  describe("cve_lookup", () => {
    it("should fetch CVE data from MITRE API successfully", async () => {
      const mockCveData = { cveMetadata: { cveId: "CVE-2021-44228" } };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData,
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" }, {});

      expect(result.isError).toBeUndefined();
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");

      const data = JSON.parse(result.content[0].text);
      expect(data.cveMetadata.cveId).toBe("CVE-2021-44228");
    });

    it("should return error if fetch fails", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found"
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-0000-0000" }, {});

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch CVE data: 404 Not Found");
    });

    it("should catch fetch errors", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network Error"));

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" }, {});

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error looking up CVE: Network Error");
    });
  });
});
