import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport to prevent real IO
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start = vi.fn();
      close = vi.fn();
    }
  };
});

// Polyfill and mock global fetch for testing CVE lookup
const originalFetch = global.fetch;

describe("MCP Server Tools", () => {
  let toolsMap: any;

  beforeEach(() => {
    // Access internal tools safely to test handlers directly
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools;

    // Setup mock fetch
    global.fetch = vi.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.clearAllMocks();
  });

  it("should have all expected tools registered", () => {
    expect(toolsMap).toBeDefined();
    const toolNames = Object.keys(toolsMap);
    expect(toolNames).toContain("list_frameworks");
    expect(toolNames).toContain("get_framework");
    expect(toolNames).toContain("audit_item");
    expect(toolNames).toContain("generate_report");
    expect(toolNames).toContain("get_risk_summary");
    expect(toolNames).toContain("search_controls");
    expect(toolNames).toContain("cve_lookup");
  });

  describe("list_frameworks", () => {
    it("should list all available frameworks", async () => {
      const handler = toolsMap["list_frameworks"].handler;
      const result = await handler({});
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      const owasp = parsed.frameworks.find((f: any) => f.id === "owasp");
      expect(owasp).toBeDefined();
      expect(owasp.name).toBe("OWASP Top 10");
    });
  });

  describe("get_framework", () => {
    it("should return the requested framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "owasp" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe("OWASP Top 10");
      expect(parsed.items.length).toBeGreaterThan(0);
    });

    it("should handle invalid framework gracefully (though zod should catch this first)", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "invalid" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item", () => {
    it("should record a result successfully", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Missing role checks"
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.status).toBe("fail");
      expect(parsed.recorded.notes).toBe("Missing role checks");
      expect(parsed.sessionProgress).toBeDefined();
    });

    it("should error if item not found", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "INVALID-ITEM",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("generate_report", () => {
    beforeEach(async () => {
      // Seed a session
      const handler = toolsMap["audit_item"].handler;
      await handler({ sessionId: "report-session", framework: "owasp", itemId: "A01", status: "pass" });
      await handler({ sessionId: "report-session", framework: "owasp", itemId: "A02", status: "fail", notes: "Bad crypto" });
    });

    it("should generate a JSON report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "json" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.session).toBe("report-session");
      expect(parsed.summary.passed).toBe(1);
      expect(parsed.summary.failed).toBe(1);
    });

    it("should generate a markdown report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "markdown" });
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("Bad crypto");
    });

    it("should generate an HTML report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "html" });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("Bad crypto");
    });

    it("should error if session not found", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "invalid-session", format: "json" });
      expect(result.isError).toBe(true);
    });
  });

  describe("get_risk_summary", () => {
    it("should return risk breakdown", async () => {
      const handler = toolsMap["get_risk_summary"].handler;
      const result = await handler({ framework: "owasp" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.framework).toBe("OWASP Top 10");
      expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
      expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe("search_controls", () => {
    it("should find controls across all frameworks", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "encrypt", framework: "all" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(parsed.results["OWASP Top 10"]).toBeDefined();
    });

    it("should find controls in a specific framework", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "encrypt", framework: "owasp" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.results["OWASP Top 10"]).toBeDefined();
      expect(parsed.results["NIST SP 800-53"]).toBeUndefined();
    });
  });

  describe("cve_lookup", () => {
    it("should return CVE details on successful API call", async () => {
      const mockCveData = { cveMetadata: { cveId: "CVE-2021-44228" } };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData,
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });
      const parsed = JSON.parse(result.content[0].text);

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
      expect(parsed).toEqual(mockCveData);
    });

    it("should return an error if API response is not ok", async () => {
      (global.fetch as any).mockResolvedValueOnce({ ok: false });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-INVALID" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found or API error");
    });

    it("should handle network errors", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network Failure"));

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error fetching CVE data: Network Failure");
    });
  });
});
