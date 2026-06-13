import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "./index.js";

const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;

describe("Security Audit MCP Server Tools", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn();
  });

  it("should have all required tools registered", () => {
    expect(toolsMap).toBeDefined();
    expect(toolsMap["list_frameworks"]).toBeDefined();
    expect(toolsMap["get_framework"]).toBeDefined();
    expect(toolsMap["audit_item"]).toBeDefined();
    expect(toolsMap["generate_report"]).toBeDefined();
    expect(toolsMap["get_risk_summary"]).toBeDefined();
    expect(toolsMap["search_controls"]).toBeDefined();
    expect(toolsMap["cve_lookup"]).toBeDefined();
  });

  describe("list_frameworks", () => {
    it("should return a list of frameworks", async () => {
      const result = await toolsMap["list_frameworks"].handler({});
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks.some((fw: any) => fw.id === "owasp")).toBe(true);
      expect(data.frameworks.some((fw: any) => fw.id === "gdpr")).toBe(true);
    });
  });

  describe("get_framework", () => {
    it("should return the full checklist for a valid framework", async () => {
      const result = await toolsMap["get_framework"].handler({ framework: "owasp" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items.length).toBeGreaterThan(0);
    });

    it("should return an error for an invalid framework", async () => {
      const result = await toolsMap["get_framework"].handler({ framework: "invalid" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item", () => {
    it("should record a pass/fail/skip result for an item", async () => {
      const result = await toolsMap["audit_item"].handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");
    });

    it("should update an existing result", async () => {
      await toolsMap["audit_item"].handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });
      const result2 = await toolsMap["audit_item"].handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
      });
      expect(result2.content[0].type).toBe("text");
      const data2 = JSON.parse(result2.content[0].text);
      expect(data2.recorded.status).toBe("fail");
    });

    it("should return an error for an invalid item id", async () => {
      const result = await toolsMap["audit_item"].handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "INVALID-ID",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("generate_report", () => {
    it("should generate a markdown report", async () => {
      await toolsMap["audit_item"].handler({
        sessionId: "test-session-report",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });
      const result = await toolsMap["generate_report"].handler({
        sessionId: "test-session-report",
        format: "markdown",
      });
      expect(result.content[0].type).toBe("text");
      expect(result.content[0].text).toContain("Security Audit Report");
      expect(result.content[0].text).toContain("OWASP Top 10");
    });

    it("should generate a json report", async () => {
       await toolsMap["audit_item"].handler({
        sessionId: "test-session-report2",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });
      const result = await toolsMap["generate_report"].handler({
        sessionId: "test-session-report2",
        format: "json",
      });
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe("test-session-report2");
      expect(data.framework).toBe("OWASP Top 10");
    });

    it("should generate an HTML report", async () => {
        await toolsMap["audit_item"].handler({
          sessionId: "test-session-report3",
          framework: "owasp",
          itemId: "A01",
          status: "pass",
        });
        const result = await toolsMap["generate_report"].handler({
          sessionId: "test-session-report3",
          format: "html",
        });
        expect(result.content[0].text).toContain("<!DOCTYPE html>");
        expect(result.content[0].text).toContain("Security Audit Report");
    });

    it("should return an error for a non-existent session", async () => {
      const result = await toolsMap["generate_report"].handler({
        sessionId: "non-existent-session",
        format: "markdown",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("get_risk_summary", () => {
    it("should return a breakdown of risks", async () => {
      const result = await toolsMap["get_risk_summary"].handler({ framework: "owasp" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown).toBeDefined();
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
    });
  });

  describe("search_controls", () => {
    it("should search for controls by keyword across all frameworks", async () => {
      const result = await toolsMap["search_controls"].handler({ query: "injection", framework: "all" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });

    it("should search for controls by keyword within a specific framework", async () => {
      const result = await toolsMap["search_controls"].handler({ query: "injection", framework: "owasp" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
      expect(data.results["NIST SP 800-53"]).toBeUndefined();
    });
  });

  describe("cve_lookup", () => {
    it("should return CVE details for a valid CVE ID", async () => {
      const mockResponse = {
        cveMetadata: { cveId: "CVE-2021-44228" },
        containers: { cna: { descriptions: [{ value: "Log4j vulnerability" }] } }
      };
      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      const result = await toolsMap["cve_lookup"].handler({ cveId: "CVE-2021-44228" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.cveMetadata.cveId).toBe("CVE-2021-44228");
    });

    it("should return an error if CVE is not found", async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 404,
      });

      const result = await toolsMap["cve_lookup"].handler({ cveId: "CVE-UNKNOWN" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle API errors", async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 500,
      });

      const result = await toolsMap["cve_lookup"].handler({ cveId: "CVE-ERROR" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error looking up CVE: API returned status 500");
    });

    it("should handle network errors", async () => {
      (global.fetch as any).mockRejectedValue(new Error("Network Error"));

      const result = await toolsMap["cve_lookup"].handler({ cveId: "CVE-NETWORK-ERROR" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error looking up CVE: Network Error");
    });
  });
});
