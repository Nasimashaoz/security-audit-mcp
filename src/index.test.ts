import { describe, it, expect, beforeEach, vi } from "vitest";
import { server, sessions } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock the stdio transport start/close for testing
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start = vi.fn();
      close = vi.fn();
    },
  };
});

describe("security-audit-mcp tools", () => {
  let toolsMap: Map<string, any>;

  beforeEach(() => {
    // Clear sessions before each test
    sessions.clear();
    // Access the tools registry safely (private property depending on SDK version)
    toolsMap = (server as any)._registeredTools || (server as any)._tools;
    if (!(toolsMap instanceof Map)) {
        // Fallback if it's an object instead of Map
        toolsMap = new Map(Object.entries(toolsMap));
    }
  });

  const runTool = async (name: string, args: any) => {
    const tool = toolsMap.get(name);
    if (!tool) throw new Error(`Tool ${name} not found`);
    // Assuming tool.handler holds the async execution logic in the mock
    return await tool.handler(args, {});
  };

  it("should list frameworks correctly", async () => {
    const response = await runTool("list_frameworks", {});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    const owasp = data.frameworks.find((f: any) => f.id === "owasp");
    expect(owasp).toBeDefined();
    expect(owasp.name).toBe("OWASP Top 10");
  });

  it("should get a specific framework", async () => {
    const response = await runTool("get_framework", { framework: "owasp" });
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
    expect(data.items.length).toBeGreaterThan(0);
  });

  it("should handle get_framework with missing framework gracefully", async () => {
    // We mock missing framework (zod schema might block this, but testing handler logic)
    const tool = toolsMap.get("get_framework");
    const response = await tool.handler({ framework: "invalid_framework" }, {});
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Framework 'invalid_framework' not found.");
  });

  it("should audit an item and update session", async () => {
    const sessionId = "test-session";
    const response = await runTool("audit_item", {
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "All good",
    });

    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.recorded.itemId).toBe("A01");
    expect(data.recorded.status).toBe("pass");

    const session = sessions.get(sessionId);
    expect(session).toBeDefined();
    expect(session?.results.length).toBe(1);
    expect(session?.results[0].itemId).toBe("A01");
  });

  it("should generate a markdown report", async () => {
    const sessionId = "test-report";
    await runTool("audit_item", {
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Needs fix",
    });

    const response = await runTool("generate_report", {
      sessionId,
      format: "markdown",
    });

    expect(response.content[0].type).toBe("text");
    const text = response.content[0].text;
    expect(text).toContain("🚨 Critical Findings");
    expect(text).toContain("Needs fix");
  });

  it("should generate a json report", async () => {
    const sessionId = "test-report-json";
    await runTool("audit_item", {
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });

    const response = await runTool("generate_report", {
      sessionId,
      format: "json",
    });

    const data = JSON.parse(response.content[0].text);
    expect(data.session).toBe(sessionId);
    expect(data.summary.passed).toBe(1);
    expect(data.score).toBe("100%");
  });

  it("should handle generate_report for missing session", async () => {
    const response = await runTool("generate_report", {
      sessionId: "invalid-session",
      format: "json",
    });
    expect(response.isError).toBe(true);
  });

  it("should get risk summary", async () => {
    const response = await runTool("get_risk_summary", { framework: "owasp" });
    const data = JSON.parse(response.content[0].text);
    expect(data.framework).toBe("OWASP Top 10");
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("should search controls", async () => {
    const response = await runTool("search_controls", { query: "encrypt", framework: "all" });
    const data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results["OWASP Top 10"]).toBeDefined();
  });

  describe("cve_lookup", () => {
    it("should lookup CVE details successfully", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id: "CVE-2021-44228", description: "Log4j" }),
      });

      const response = await runTool("cve_lookup", { cveId: "CVE-2021-44228" });
      const data = JSON.parse(response.content[0].text);
      expect(data.id).toBe("CVE-2021-44228");
    });

    it("should handle CVE not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      const response = await runTool("cve_lookup", { cveId: "CVE-INVALID" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it("should handle fetch error", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

      const response = await runTool("cve_lookup", { cveId: "CVE-INVALID" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Network Error");
    });
  });
});
