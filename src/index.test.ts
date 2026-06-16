import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport since real stdio cannot be connected in tests
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class StdioServerTransport {
      start = vi.fn();
      close = vi.fn();
    },
  };
});

// We can extract tools safely via internal registry as per memories.
const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;

describe("MCP Tools", () => {

  describe("list_frameworks", () => {
    it("should return a list of all available frameworks", async () => {
      const handler = toolsMap["list_frameworks"].handler;
      const result = await handler({});
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(data.frameworks.some((fw: any) => fw.id === "owasp")).toBe(true);
      expect(data.frameworks.some((fw: any) => fw.id === "pcidss")).toBe(true);
    });
  });

  describe("get_framework", () => {
    it("should return the correct framework details for a given valid framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "owasp" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe(FRAMEWORKS.owasp.name);
      expect(data.items.length).toBeGreaterThan(0);
    });

    it("should return an error for an invalid framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "invalid" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item and generate_report", () => {
    const sessionId = "test-session-123";

    it("should successfully audit a valid item", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId,
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Missing role validation"
      });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("fail");
    });

    it("should return an error when auditing an invalid item", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId,
        framework: "owasp",
        itemId: "INVALID-ID",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should generate a report in json format", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId, format: "json" });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe(sessionId);
      expect(data.summary.failed).toBe(1);
    });

    it("should generate a report in markdown format", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId, format: "markdown" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("A01");
    });

    it("should generate a report in html format", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId, format: "html" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("A01");
    });

    it("should return an error when generating a report for a missing session", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "invalid-session", format: "json" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("get_risk_summary", () => {
    it("should return a risk summary for a framework", async () => {
      const handler = toolsMap["get_risk_summary"].handler;
      const result = await handler({ framework: "owasp" });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe(FRAMEWORKS.owasp.name);
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
    });
  });

  describe("search_controls", () => {
    it("should find controls matching a query", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "injection", framework: "all" });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results[FRAMEWORKS.owasp.name]).toBeDefined();
    });

    it("should find controls within a specific framework", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "injection", framework: "owasp" });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.results[FRAMEWORKS.owasp.name]).toBeDefined();
      expect(Object.keys(data.results).length).toBe(1);
    });
  });

  describe("cve_lookup", () => {
    beforeAll(() => {
      global.fetch = vi.fn();
    });

    it("should return CVE details for a valid CVE", async () => {
      const mockResponse = { id: "CVE-2021-44228", description: "Log4j" };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe("CVE-2021-44228");
    });

    it("should return an error for a non-existent CVE", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-0000-0000" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should return an error for API failure", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch");
    });
  });
});
