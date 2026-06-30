import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => ({
      start: vi.fn(),
      close: vi.fn(),
    })),
  };
});

// Helper to access tools
const getTool = (name: string) => {
  const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools || (server as any).tools;
  if (!toolsMap || !toolsMap[name]) {
    throw new Error(`Tool ${name} not found`);
  }
  return toolsMap[name];
};

describe("security-audit-mcp tools", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
    global.fetch = vi.fn();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe("list_frameworks", () => {
    it("should list all frameworks", async () => {
      const tool = getTool("list_frameworks");
      const result = await tool.handler({});
      expect(result.content[0].text).toContain("owasp");
      expect(result.content[0].text).toContain("nist");
      expect(result.content[0].text).toContain("iso27001");
    });
  });

  describe("get_framework", () => {
    it("should return the full checklist for a specific framework", async () => {
      const tool = getTool("get_framework");
      const result = await tool.handler({ framework: "owasp" }, {});
      expect(result.content[0].text).toContain("OWASP Top 10");
      expect(result.content[0].text).toContain("A01");
    });

    it("should return an error if framework is not found", async () => {
      const tool = getTool("get_framework");
      const result = await tool.handler({ framework: "unknown" }, {});
      expect(result.isError).toBe(true);
    });
  });

  describe("get_risk_summary", () => {
    it("should return a breakdown of risks by severity level for a framework", async () => {
      const tool = getTool("get_risk_summary");
      const result = await tool.handler({ framework: "owasp" }, {});
      const text = result.content[0].text;
      const data = JSON.parse(text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
    });
  });

  describe("search_controls", () => {
    it("should search for security controls by keyword across all frameworks", async () => {
      const tool = getTool("search_controls");
      const result = await tool.handler({ query: "injection", framework: "all" }, {});
      const text = result.content[0].text;
      const data = JSON.parse(text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });
  });

  describe("audit_item", () => {
    it("should record a pass/fail/skip result for a specific audit control item", async () => {
      const tool = getTool("audit_item");
      const result = await tool.handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      }, {});
      const text = result.content[0].text;
      const data = JSON.parse(text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");
      expect(data.sessionProgress).toContain("1 /");
    });
  });

  describe("cve_lookup", () => {
    it("should look up a CVE from MITRE", async () => {
      const mockResponse = {
        cveMetadata: {
          cveId: "CVE-2021-44228"
        }
      };

      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      const tool = getTool("cve_lookup");
      const result = await tool.handler({ cveId: "CVE-2021-44228" }, {});

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");

      const text = result.content[0].text;
      const data = JSON.parse(text);
      expect(data.cveMetadata.cveId).toBe("CVE-2021-44228");
    });

    it("should handle lookup errors gracefully", async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      const tool = getTool("cve_lookup");
      const result = await tool.handler({ cveId: "CVE-UNKNOWN" }, {});

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to lookup CVE-UNKNOWN: 404 Not Found");
    });
  });

  describe("generate_report", () => {
    it("should generate a full audit report for a session in markdown", async () => {
      const auditTool = getTool("audit_item");
      await auditTool.handler({
        sessionId: "test-session-2",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      }, {});

      const reportTool = getTool("generate_report");
      const result = await reportTool.handler({
        sessionId: "test-session-2",
        format: "markdown",
      }, {});

      const text = result.content[0].text;
      expect(text).toContain("Security Audit Report");
      expect(text).toContain("OWASP Top 10");
      expect(text).toContain("A01");
      expect(text).toContain("2024-01-01T00:00:00.000Z");
    });

    it("should generate a full audit report for a session in json", async () => {
      const auditTool = getTool("audit_item");
      await auditTool.handler({
        sessionId: "test-session-3",
        framework: "nist",
        itemId: "AC-1",
        status: "fail",
      }, {});

      const reportTool = getTool("generate_report");
      const result = await reportTool.handler({
        sessionId: "test-session-3",
        format: "json",
      }, {});

      const text = result.content[0].text;
      const data = JSON.parse(text);
      expect(data.framework).toBe("NIST SP 800-53");
      expect(data.summary.failed).toBe(1);
      expect(data.generatedAt).toBe("2024-01-01T00:00:00.000Z");
    });
  });
});
