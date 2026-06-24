import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server, main } from "./index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
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

describe("security-audit-mcp server", () => {
  let toolsMap: any;

  beforeEach(() => {
    // Access registered tools map for direct invocation
    toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should have correct tools registered", () => {
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
    it("should list all available frameworks", async () => {
      const handler = toolsMap["list_frameworks"].handler;
      const response = await handler({});

      const content = JSON.parse(response.content[0].text);
      expect(content.frameworks).toBeInstanceOf(Array);
      expect(content.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      const owasp = content.frameworks.find((f: any) => f.id === "owasp");
      expect(owasp).toBeDefined();
      expect(owasp.name).toBe("OWASP Top 10");
    });
  });

  describe("get_framework", () => {
    it("should return the correct framework data", async () => {
      const handler = toolsMap["get_framework"].handler;
      const response = await handler({ framework: "nist" });

      const content = JSON.parse(response.content[0].text);
      expect(content.name).toBe("NIST SP 800-53");
      expect(content.items).toBeInstanceOf(Array);
      expect(content.items[0].id).toBe("AC-1");
    });

    it("should return an error for unknown framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      // It should still catch errors via runtime fallback if type validation passes
      const response = await handler({ framework: "unknown" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("audit_item", () => {
    it("should add a successful audit item to the session", async () => {
      const handler = toolsMap["audit_item"].handler;
      const response = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });

      const content = JSON.parse(response.content[0].text);
      expect(content.recorded.itemId).toBe("A01");
      expect(content.recorded.status).toBe("pass");
      expect(content.recorded.notes).toBe("Looks good");
    });

    it("should return an error if item is not found in framework", async () => {
      const handler = toolsMap["audit_item"].handler;
      const response = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "INVALID-ITEM",
        status: "pass",
      });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("generate_report", () => {
    beforeEach(async () => {
      // Setup session
      const handler = toolsMap["audit_item"].handler;
      await handler({ sessionId: "report-session", framework: "owasp", itemId: "A01", status: "pass" });
      await handler({ sessionId: "report-session", framework: "owasp", itemId: "A02", status: "fail", notes: "Bad crypto" });
    });

    it("should return error for unknown session", async () => {
      const handler = toolsMap["generate_report"].handler;
      const response = await handler({ sessionId: "unknown", format: "json" });
      expect(response.isError).toBe(true);
    });

    it("should generate a JSON report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const response = await handler({ sessionId: "report-session", format: "json" });

      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe("report-session");
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.generatedAt).toBe("2024-01-01T12:00:00.000Z");
    });

    it("should generate a Markdown report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const response = await handler({ sessionId: "report-session", format: "markdown" });

      const text = response.content[0].text;
      expect(text).toContain("# 🔒 Security Audit Report");
      expect(text).toContain("Bad crypto");
    });

    it("should generate an HTML report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const response = await handler({ sessionId: "report-session", format: "html" });

      const text = response.content[0].text;
      expect(text).toContain("<!DOCTYPE html>");
      expect(text).toContain("<td>A01</td>");
    });
  });

  describe("get_risk_summary", () => {
    it("should summarize risks for a framework", async () => {
      const handler = toolsMap["get_risk_summary"].handler;
      const response = await handler({ framework: "iso27001" });

      const data = JSON.parse(response.content[0].text);
      expect(data.framework).toBe("ISO 27001");
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe("search_controls", () => {
    it("should search controls across all frameworks", async () => {
      const handler = toolsMap["search_controls"].handler;
      const response = await handler({ query: "encrypt", framework: "all" });

      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });

    it("should search controls in a specific framework", async () => {
      const handler = toolsMap["search_controls"].handler;
      const response = await handler({ query: "authentication", framework: "nist" });

      const data = JSON.parse(response.content[0].text);
      expect(data.results["NIST SP 800-53"]).toBeDefined();
      expect(data.results["OWASP Top 10"]).toBeUndefined();
    });
  });

  describe("cve_lookup", () => {
    it("should fetch and return CVE data", async () => {
      const mockResponse = { id: "CVE-2021-44228", description: "Log4Shell" };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: vi.fn().mockResolvedValue(mockResponse),
      });

      const handler = toolsMap["cve_lookup"].handler;
      const response = await handler({ cveId: "CVE-2021-44228" });

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
      const data = JSON.parse(response.content[0].text);
      expect(data.id).toBe("CVE-2021-44228");
    });

    it("should handle 404 properly", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      const handler = toolsMap["cve_lookup"].handler;
      const response = await handler({ cveId: "CVE-UNKNOWN" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it("should handle server errors gracefully", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Failure"));

      const handler = toolsMap["cve_lookup"].handler;
      const response = await handler({ cveId: "CVE-2021-44228" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Network Failure");
    });
  });
});
