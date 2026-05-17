import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "./index.js";

// Mock the StdioServerTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => ({
      // mock transport methods if necessary
    })),
  };
});

describe("security-audit-mcp server tools", () => {
  const tools = (server as any)._registeredTools;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("list_frameworks should return available frameworks", async () => {
    const handler = tools["list_frameworks"].handler;
    const result = await handler({});
    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.frameworks.length).toBeGreaterThan(0);
  });

  it("get_framework should return a framework", async () => {
    const handler = tools["get_framework"].handler;
    const result = await handler({ framework: "owasp" });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.name).toBe("OWASP Top 10");
  });

  it("get_framework should return error for unknown framework", async () => {
    // Note: Zod validation handles this at the framework level usually,
    // but we can test the handler directly.
    const handler = tools["get_framework"].handler;
    const result = await handler({ framework: "unknown" });
    expect(result.isError).toBe(true);
  });

  it("audit_item should record an audit result", async () => {
    const handler = tools["audit_item"].handler;
    const result = await handler({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Found an issue",
    });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.recorded.itemId).toBe("A01");
    expect(parsed.recorded.status).toBe("fail");
  });

  it("audit_item should return error for unknown item", async () => {
    const handler = tools["audit_item"].handler;
    const result = await handler({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "UNKNOWN-ITEM",
      status: "fail",
    });
    expect(result.isError).toBe(true);
  });

  it("generate_report should generate a report in markdown", async () => {
    // First, add an item
    await tools["audit_item"].handler({
      sessionId: "report-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Critical issue",
    });

    const handler = tools["generate_report"].handler;
    const result = await handler({ sessionId: "report-session", format: "markdown" });
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("Security Audit Report");
    expect(result.content[0].text).toContain("A01");
  });

  it("generate_report should generate a report in json", async () => {
    const handler = tools["generate_report"].handler;
    const result = await handler({ sessionId: "report-session", format: "json" });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.session).toBe("report-session");
    expect(parsed.framework).toBe("OWASP Top 10");
  });

  it("generate_report should generate a report in html", async () => {
    const handler = tools["generate_report"].handler;
    const result = await handler({ sessionId: "report-session", format: "html" });
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("<!DOCTYPE html>");
  });

  it("generate_report should return error for unknown session", async () => {
    const handler = tools["generate_report"].handler;
    const result = await handler({ sessionId: "unknown-session", format: "markdown" });
    expect(result.isError).toBe(true);
  });

  it("get_risk_summary should return breakdown of risks", async () => {
    const handler = tools["get_risk_summary"].handler;
    const result = await handler({ framework: "owasp" });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.riskBreakdown).toBeDefined();
    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
  });

  it("search_controls should find controls", async () => {
    const handler = tools["search_controls"].handler;
    const result = await handler({ query: "injection", framework: "all" });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(parsed.results["OWASP Top 10"]).toBeDefined();
  });

  it("cve_lookup should fetch CVE data successfully", async () => {
    const mockData = { id: "CVE-2021-44228", description: "Log4j vulnerability" };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockData,
    });

    const handler = tools["cve_lookup"].handler;
    const result = await handler({ cveId: "CVE-2021-44228" });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.id).toBe("CVE-2021-44228");
    expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
  });

  it("cve_lookup should handle fetch errors", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      statusText: "Not Found",
    });

    const handler = tools["cve_lookup"].handler;
    const result = await handler({ cveId: "CVE-UNKNOWN" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Failed to fetch CVE");
  });

  it("cve_lookup should handle network errors", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

    const handler = tools["cve_lookup"].handler;
    const result = await handler({ cveId: "CVE-2021-44228" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Error fetching CVE");
  });
});
