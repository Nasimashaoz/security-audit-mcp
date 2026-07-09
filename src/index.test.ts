import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server, main } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock transport to avoid testing actual stdio connections
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      constructor() {}
    },
  };
});

describe("security-audit-mcp", () => {
  let toolsMap: any;

  beforeEach(() => {
    // Access internal tools registry
    toolsMap = (server as any)._registeredTools;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should have registered all expected tools", () => {
    expect(toolsMap["list_frameworks"]).toBeDefined();
    expect(toolsMap["get_framework"]).toBeDefined();
    expect(toolsMap["audit_item"]).toBeDefined();
    expect(toolsMap["generate_report"]).toBeDefined();
    expect(toolsMap["get_risk_summary"]).toBeDefined();
    expect(toolsMap["search_controls"]).toBeDefined();
    expect(toolsMap["cve_lookup"]).toBeDefined();
  });

  it("list_frameworks should return all available frameworks", async () => {
    const handler = toolsMap["list_frameworks"].handler;
    const result = await handler({}, { /* extra args */ });
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    expect(data.frameworks[0].id).toBe("owasp");
  });

  it("get_framework should return specific framework details", async () => {
    const handler = toolsMap["get_framework"].handler;
    const result = await handler({ framework: "owasp" }, {});
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
  });

  it("get_framework should return an error if framework is not found", async () => {
    const handler = toolsMap["get_framework"].handler;
    const result = await handler({ framework: "nonexistent" }, {});
    expect(result.isError).toBe(true);
  });

  it("audit_item should record a result and update session", async () => {
    const handler = toolsMap["audit_item"].handler;
    const result = await handler({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Test note"
    }, {});

    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.recorded.itemId).toBe("A01");
    expect(data.recorded.status).toBe("fail");
  });

  it("audit_item should return an error if item is not found", async () => {
    const handler = toolsMap["audit_item"].handler;
    const result = await handler({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "invalid-item",
      status: "pass"
    }, {});

    expect(result.isError).toBe(true);
  });

  it("generate_report should return a markdown report by default", async () => {
    // First, add an item
    await toolsMap["audit_item"].handler({
      sessionId: "report-session",
      framework: "nist",
      itemId: "AC-1",
      status: "pass"
    }, {});

    const handler = toolsMap["generate_report"].handler;
    const result = await handler({ sessionId: "report-session", format: "markdown" }, {});
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
    expect(result.content[0].text).toContain("Score:** 100%");
  });

  it("generate_report should return a json report if specified", async () => {
    await toolsMap["audit_item"].handler({
      sessionId: "report-session-json",
      framework: "nist",
      itemId: "AC-1",
      status: "pass"
    }, {});

    const handler = toolsMap["generate_report"].handler;
    const result = await handler({ sessionId: "report-session-json", format: "json" }, {});
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.score).toBe("100%");
    expect(data.summary.passed).toBe(1);
  });

  it("generate_report should return a html report if specified", async () => {
    await toolsMap["audit_item"].handler({
      sessionId: "report-session-html",
      framework: "nist",
      itemId: "AC-1",
      status: "fail",
      notes: "test HTML format note"
    }, {});

    const handler = toolsMap["generate_report"].handler;
    const result = await handler({ sessionId: "report-session-html", format: "html" }, {});
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("<!DOCTYPE html>");
    expect(result.content[0].text).toContain("AC-1");
  });

  it("generate_report should return an error if session is not found", async () => {
    const handler = toolsMap["generate_report"].handler;
    const result = await handler({ sessionId: "nonexistent-session", format: "json" }, {});
    expect(result.isError).toBe(true);
  });

  it("get_risk_summary should group risks by severity", async () => {
    const handler = toolsMap["get_risk_summary"].handler;
    const result = await handler({ framework: "owasp" }, {});
    const data = JSON.parse(result.content[0].text);
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
  });

  it("search_controls should find controls by keyword", async () => {
    const handler = toolsMap["search_controls"].handler;
    const result = await handler({ query: "injection", framework: "all" }, {});
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results["OWASP Top 10"]).toBeDefined();
  });

  it("search_controls should find controls by keyword within specific framework", async () => {
    const handler = toolsMap["search_controls"].handler;
    const result = await handler({ query: "injection", framework: "owasp" }, {});
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results["OWASP Top 10"]).toBeDefined();
    expect(data.results["NIST SP 800-53"]).toBeUndefined();
  });

  describe("cve_lookup tool", () => {
    it("should fetch and return CVE details on success", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          cveMetadata: { cveId: "CVE-2021-44228" },
        }),
      } as any);

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" }, {});
      const data = JSON.parse(result.content[0].text);
      expect(data.cveMetadata.cveId).toBe("CVE-2021-44228");
    });

    it("should return an error message on 404", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      } as any);

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-UNKNOWN" }, {});
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should return an error message on other fetch failures", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error",
      } as any);

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-ERROR" }, {});
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Internal Server Error");
    });

    it("should handle exceptions during fetch", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-FAIL" }, {});
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Network Error");
    });
  });

  describe("main server initialization", () => {
    it("should connect transport and log started message", async () => {
      const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      server.connect = vi.fn().mockResolvedValue(undefined) as any;

      await main();

      expect(server.connect).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith("🔐 security-audit-mcp server running on stdio");
    });
  });
});
