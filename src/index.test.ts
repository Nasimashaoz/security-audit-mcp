import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

const getToolsMap = () => (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

describe("MCP Server Tools", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
  });

  it("should list frameworks", async () => {
    const tools = getToolsMap();
    const result = await tools["list_frameworks"].handler({});
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
  });

  it("should get a specific framework", async () => {
    const tools = getToolsMap();
    const result = await tools["get_framework"].handler({ framework: "owasp" });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.name).toBe("OWASP Top 10");
  });

  it("should handle get_framework with invalid framework", async () => {
    const tools = getToolsMap();
    const result = await tools["get_framework"].handler({ framework: "invalid" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("should audit an item", async () => {
    const tools = getToolsMap();
    const result = await tools["audit_item"].handler({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Failed access control"
    });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.recorded.itemId).toBe("A01");
    expect(parsed.recorded.status).toBe("fail");
  });

  it("should handle audit_item with invalid item", async () => {
    const tools = getToolsMap();
    const result = await tools["audit_item"].handler({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "INVALID",
      status: "fail",
      notes: "Failed access control"
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("should generate report in markdown", async () => {
    const tools = getToolsMap();
    const result = await tools["generate_report"].handler({
      sessionId: "test-session",
      format: "markdown"
    });
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("Security Audit Report");
  });

  it("should generate report in json", async () => {
    const tools = getToolsMap();
    const result = await tools["generate_report"].handler({
      sessionId: "test-session",
      format: "json"
    });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.session).toBe("test-session");
  });

  it("should generate report in html", async () => {
    const tools = getToolsMap();
    const result = await tools["generate_report"].handler({
      sessionId: "test-session",
      format: "html"
    });
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("<!DOCTYPE html>");
  });

  it("should handle generate_report with invalid session", async () => {
    const tools = getToolsMap();
    const result = await tools["generate_report"].handler({
      sessionId: "invalid-session",
      format: "markdown"
    });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("should get risk summary", async () => {
    const tools = getToolsMap();
    const result = await tools["get_risk_summary"].handler({
      framework: "owasp"
    });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("should search controls", async () => {
    const tools = getToolsMap();
    const result = await tools["search_controls"].handler({
      query: "injection",
      framework: "all"
    });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
  });

  describe("cve_lookup tool", () => {
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
      originalFetch = global.fetch;
      global.fetch = vi.fn() as any;
    });

    afterEach(() => {
      global.fetch = originalFetch as any;
    });

    it("should successfully look up a valid CVE", async () => {
      const mockCveData = { cveMetadata: { cveId: "CVE-2021-44228" } };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockCveData),
      });

      const tools = getToolsMap();
      const result = await tools["cve_lookup"].handler({ cveId: "CVE-2021-44228" });

      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.cveMetadata.cveId).toBe("CVE-2021-44228");
    });

    it("should handle 404 for missing CVE", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const tools = getToolsMap();
      const result = await tools["cve_lookup"].handler({ cveId: "CVE-9999-99999" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle API errors", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const tools = getToolsMap();
      const result = await tools["cve_lookup"].handler({ cveId: "CVE-2021-44228" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to look up CVE");
    });

    it("should handle cve_lookup fetch rejection", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network Error"));

      const tools = getToolsMap();
      const result = await tools["cve_lookup"].handler({ cveId: "CVE-2021-44228" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to look up CVE");
    });
  });

});
