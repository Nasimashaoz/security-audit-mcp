
import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "./index.js";

// Mock StdioServerTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    }
  };
});

const toolsMap = (server as any)._registeredTools || (server as any).registeredTools || (server as any).server?.registeredTools;

describe("MCP Server Tools", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("should have all tools registered", () => {
    expect(toolsMap).toBeDefined();
    expect(toolsMap["list_frameworks"]).toBeDefined();
    expect(toolsMap["get_framework"]).toBeDefined();
    expect(toolsMap["audit_item"]).toBeDefined();
    expect(toolsMap["generate_report"]).toBeDefined();
    expect(toolsMap["get_risk_summary"]).toBeDefined();
    expect(toolsMap["search_controls"]).toBeDefined();
    expect(toolsMap["cve_lookup"]).toBeDefined();
  });

  it("list_frameworks should return available frameworks", async () => {
    const handler = toolsMap["list_frameworks"].handler;
    const result = await handler({});
    const data = JSON.parse(result.content[0].text);
    expect(data.frameworks.length).toBeGreaterThan(0);
    expect(data.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === "pcidss")).toBe(true); // newly added
  });

  it("get_framework should return a specific framework", async () => {
    const handler = toolsMap["get_framework"].handler;
    const result = await handler({ framework: "owasp" });
    const data = JSON.parse(result.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
  });

  it("get_framework should return error for invalid framework", async () => {
    const handler = toolsMap["get_framework"].handler;
    const result = await handler({ framework: "invalid" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("audit_item should record a result", async () => {
    const handler = toolsMap["audit_item"].handler;
    const result = await handler({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "All good"
    });
    const data = JSON.parse(result.content[0].text);
    expect(data.recorded.itemId).toBe("A01");
    expect(data.recorded.status).toBe("pass");
  });

  it("audit_item should return error for invalid item", async () => {
    const handler = toolsMap["audit_item"].handler;
    const result = await handler({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "INVALID-ITEM",
      status: "pass"
    });
    expect(result.isError).toBe(true);
  });

  it("generate_report should generate a markdown report", async () => {
    const handler = toolsMap["generate_report"].handler;
    const result = await handler({
      sessionId: "test-session",
      format: "markdown"
    });
    expect(result.content[0].text).toContain("Security Audit Report");
    expect(result.content[0].text).toContain("OWASP Top 10");
    expect(result.content[0].text).toContain("A01");
  });

  it("generate_report should generate a json report", async () => {
    const handler = toolsMap["generate_report"].handler;
    const result = await handler({
      sessionId: "test-session",
      format: "json"
    });
    const data = JSON.parse(result.content[0].text);
    expect(data.session).toBe("test-session");
  });

  it("generate_report should generate an html report", async () => {
    const handler = toolsMap["generate_report"].handler;
    const result = await handler({
      sessionId: "test-session",
      format: "html"
    });
    expect(result.content[0].text).toContain("<!DOCTYPE html>");
  });

  it("generate_report should handle missing session", async () => {
    const handler = toolsMap["generate_report"].handler;
    const result = await handler({
      sessionId: "missing-session",
      format: "markdown"
    });
    expect(result.isError).toBe(true);
  });

  it("get_risk_summary should return risk breakdown", async () => {
    const handler = toolsMap["get_risk_summary"].handler;
    const result = await handler({ framework: "owasp" });
    const data = JSON.parse(result.content[0].text);
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("search_controls should find controls by query", async () => {
    const handler = toolsMap["search_controls"].handler;
    const result = await handler({ query: "injection", framework: "all" });
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
  });

  it("search_controls should handle case-insensitive query", async () => {
    const handler = toolsMap["search_controls"].handler;
    const result = await handler({ query: "INJECTION", framework: "owasp" });
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
  });


  it("cve_lookup should fetch CVE details successfully", async () => {
    const mockResponse = { id: "CVE-2021-44228", description: "Log4j vulnerability" };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockResponse
    });

    const handler = toolsMap["cve_lookup"].handler;
    const result = await handler({ cveId: "CVE-2021-44228" });
    const data = JSON.parse(result.content[0].text);
    expect(data.id).toBe("CVE-2021-44228");
    expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
  });

  it("cve_lookup should handle 404 error", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404
    });

    const handler = toolsMap["cve_lookup"].handler;
    const result = await handler({ cveId: "CVE-INVALID" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("cve_lookup should handle other HTTP errors", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500
    });

    const handler = toolsMap["cve_lookup"].handler;
    const result = await handler({ cveId: "CVE-2021-44228" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("HTTP error! status: 500");
  });

  it("cve_lookup should handle fetch failures", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

    const handler = toolsMap["cve_lookup"].handler;
    const result = await handler({ cveId: "CVE-2021-44228" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Network Error");
  });

  it("audit_item should update existing result", async () => {
    const handler = toolsMap["audit_item"].handler;
    await handler({
      sessionId: "update-session",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });
    const result2 = await handler({
      sessionId: "update-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
    });
    const data = JSON.parse(result2.content[0].text);
    expect(data.recorded.status).toBe("fail");
  });
});

describe("Additional Coverage", () => {
  it("generate_report should include critical findings in markdown", async () => {
    const handler = toolsMap["audit_item"].handler;
    await handler({
      sessionId: "critical-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Critical risk note"
    });
    const reportHandler = toolsMap["generate_report"].handler;
    const result = await reportHandler({
      sessionId: "critical-session",
      format: "markdown"
    });
    expect(result.content[0].text).toContain("🚨 Critical Findings");
    expect(result.content[0].text).toContain("Critical risk note");
  });
});
