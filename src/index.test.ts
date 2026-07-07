import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server, sessions } from "./index.js";

// Access the internal tool registry from the McpServer instance
// Note: This relies on private SDK state. For full integration testing
// without accessing private internals, use a mock transport and test the
// handlers directly via the Client API.
const toolsMap = (server as any)._registeredTools;

describe("Security Audit MCP Server", () => {
  beforeEach(() => {
    sessions.clear();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2023-01-01T00:00:00.000Z"));
    global.fetch = vi.fn() as any;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("should have correct environment setup", () => {
    expect(toolsMap).toBeDefined();
    expect(process.env.NODE_ENV).toBe("test");
  });

  describe("list_frameworks", () => {
    it("should list all available frameworks", async () => {
      const handler = toolsMap["list_frameworks"].handler;
      const result = await handler({});
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeInstanceOf(Array);
      expect(data.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
      expect(data.frameworks.some((f: any) => f.id === "gdpr")).toBe(true);
    });
  });

  describe("get_framework", () => {
    it("should get details of a specific framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
    });

    it("should return error for invalid framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "invalid" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item", () => {
    it("should record an audit item successfully", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.status).toBe("pass");

      const session = sessions.get("test-session");
      expect(session).toBeDefined();
      expect(session?.results).toHaveLength(1);
    });

    it("should handle missing item in framework", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "INVALID",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("generate_report", () => {
    it("should return error for invalid session", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "missing", format: "json" });
      expect(result.isError).toBe(true);
    });

    it("should generate a JSON report", async () => {
      // Setup session
      const auditHandler = toolsMap["audit_item"].handler;
      await auditHandler({ sessionId: "report-sess", framework: "owasp", itemId: "A01", status: "pass" });
      await auditHandler({ sessionId: "report-sess", framework: "owasp", itemId: "A02", status: "fail" });

      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-sess", format: "json" });
      const data = JSON.parse(result.content[0].text);
      expect(data.score).toBe("50%");
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
    });

    it("should generate a markdown report", async () => {
      const auditHandler = toolsMap["audit_item"].handler;
      await auditHandler({ sessionId: "report-sess", framework: "owasp", itemId: "A01", status: "pass" });

      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-sess", format: "markdown" });
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("100%");
    });

    it("should generate an HTML report", async () => {
      const auditHandler = toolsMap["audit_item"].handler;
      await auditHandler({ sessionId: "report-sess", framework: "owasp", itemId: "A01", status: "pass" });

      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-sess", format: "html" });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("100%");
    });
  });

  describe("get_risk_summary", () => {
    it("should return risk summary for a framework", async () => {
      const handler = toolsMap["get_risk_summary"].handler;
      const result = await handler({ framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe("search_controls", () => {
    it("should search controls across all frameworks", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "encrypt", framework: "all" });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });

    it("should search controls in a specific framework", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "injection", framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });
  });

  describe("cve_lookup", () => {
    it("should successfully look up a CVE", async () => {
      const mockResponse = { cveId: "CVE-2021-44228", description: "Log4j vulnerability" };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.cveId).toBe("CVE-2021-44228");
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle CVE not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-9999-99999" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle API error", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network error"));

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error looking up CVE: Network error");
    });
  });
});
