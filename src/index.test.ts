import { describe, it, expect, beforeEach, vi } from "vitest";
import { server, sessions } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock global fetch for external APIs
global.fetch = vi.fn();

describe("security-audit-mcp server", () => {
  let toolsMap: any;

  beforeEach(() => {
    sessions.clear();
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
    vi.clearAllMocks();
  });

  describe("list_frameworks tool", () => {
    it("should list all available frameworks", async () => {
      const handler = toolsMap["list_frameworks"];
      expect(handler).toBeDefined();

      const result = await handler.handler({});
      expect(result.content[0].type).toBe("text");

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks).toHaveLength(Object.keys(FRAMEWORKS).length);
      expect(parsed.frameworks[0]).toHaveProperty("id");
      expect(parsed.frameworks[0]).toHaveProperty("name");
    });
  });

  describe("get_framework tool", () => {
    it("should return the specified framework", async () => {
      const handler = toolsMap["get_framework"];
      expect(handler).toBeDefined();

      const result = await handler.handler({ framework: "owasp" });
      expect(result.content[0].type).toBe("text");

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe(FRAMEWORKS.owasp.name);
      expect(parsed.items).toBeDefined();
    });

    it("should return an error for non-existent frameworks", async () => {
      // In zod we validated this, but let's test handler directly if possible, or assume validation happens earlier.
      // The Zod enum will prevent this but we can test the handler logic just in case it's called internally.
      const handler = toolsMap["get_framework"];
      const result = await handler.handler({ framework: "invalid_fw" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item tool", () => {
    it("should record a pass result", async () => {
      const handler = toolsMap["audit_item"];
      const sessionId = "session-1";
      const result = await handler.handler({
        sessionId,
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });

      expect(result.content[0].type).toBe("text");
      const session = sessions.get(sessionId);
      expect(session).toBeDefined();
      expect(session!.results).toHaveLength(1);
      expect(session!.results[0].status).toBe("pass");
      expect(session!.results[0].notes).toBe("Looks good");
    });

    it("should return error for invalid item id", async () => {
      const handler = toolsMap["audit_item"];
      const result = await handler.handler({
        sessionId: "session-2",
        framework: "owasp",
        itemId: "INVALID-99",
        status: "fail",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("generate_report tool", () => {
    it("should generate a markdown report", async () => {
      // First add an item
      await toolsMap["audit_item"].handler({
        sessionId: "test-report",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });

      const handler = toolsMap["generate_report"];
      const result = await handler.handler({ sessionId: "test-report", format: "markdown" });

      expect(result.content[0].type).toBe("text");
      expect(result.content[0].text).toContain("Security Audit Report");
      expect(result.content[0].text).toContain("OWASP Top 10");
      expect(result.content[0].text).toContain("A01");
    });

    it("should generate a JSON report", async () => {
      // First add an item
      await toolsMap["audit_item"].handler({
        sessionId: "test-report",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
      });

      const handler = toolsMap["generate_report"];
      const result = await handler.handler({ sessionId: "test-report", format: "json" });

      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.score).toBeDefined();
      expect(parsed.summary.failed).toBe(1);
    });

    it("should generate HTML report", async () => {
        // First add an item
      await toolsMap["audit_item"].handler({
        sessionId: "test-report",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
      });

      const handler = toolsMap["generate_report"];
      const result = await handler.handler({ sessionId: "test-report", format: "html" });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("A01");
    });

    it("should return error for invalid session", async () => {
      const handler = toolsMap["generate_report"];
      const result = await handler.handler({ sessionId: "non-existent", format: "json" });
      expect(result.isError).toBe(true);
    });
  });

  describe("get_risk_summary tool", () => {
    it("should summarize risks for a framework", async () => {
      const handler = toolsMap["get_risk_summary"];
      const result = await handler.handler({ framework: "owasp" });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
      expect(parsed.riskBreakdown.HIGH).toBeDefined();
      expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe("cve_lookup tool", () => {
    it("should fetch CVE details successfully", async () => {
      const handler = toolsMap["cve_lookup"];
      const mockCveData = { cveMetadata: { cveId: "CVE-2021-44228" } };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData,
      });

      const result = await handler.handler({ cveId: "CVE-2021-44228" });

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed).toEqual(mockCveData);
    });

    it("should return error for non-existent CVE (404)", async () => {
      const handler = toolsMap["cve_lookup"];

      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const result = await handler.handler({ cveId: "CVE-INVALID-123" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle general fetch errors", async () => {
      const handler = toolsMap["cve_lookup"];

      (global.fetch as any).mockRejectedValueOnce(new Error("Network failure"));

      const result = await handler.handler({ cveId: "CVE-2021-44228" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Network failure");
    });

    it("should handle non-ok fetch responses", async () => {
      const handler = toolsMap["cve_lookup"];

      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      const result = await handler.handler({ cveId: "CVE-2021-44228" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch CVE data: Internal Server Error");
    });
  });

  describe("search_controls tool", () => {
    it("should find controls across all frameworks", async () => {
      const handler = toolsMap["search_controls"];
      const result = await handler.handler({ query: "encrypt", framework: "all" });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(parsed.results).toBeDefined();
    });

    it("should find controls in a specific framework", async () => {
      const handler = toolsMap["search_controls"];
      const result = await handler.handler({ query: "encrypt", framework: "owasp" });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(parsed.results["OWASP Top 10"]).toBeDefined();
      expect(parsed.results["NIST SP 800-53"]).toBeUndefined();
    });
  });
});
