import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server } from "./index";

describe("security-audit-mcp tools", () => {
  let toolsMap: Record<string, any>;

  beforeEach(() => {
    // Access internal registered tools
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools || {};
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("list_frameworks should return available frameworks", async () => {
    const handler = toolsMap["list_frameworks"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({}, {});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.frameworks.some((fw: any) => fw.id === "owasp")).toBe(true);
    expect(data.frameworks.some((fw: any) => fw.id === "gdpr")).toBe(true);
    expect(data.frameworks.some((fw: any) => fw.id === "soc2")).toBe(true);
  });

  it("get_framework should return framework details for valid framework", async () => {
    const handler = toolsMap["get_framework"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({ framework: "owasp" }, {});
    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
    expect(data.items.length).toBeGreaterThan(0);
  });

  it("get_framework should return error for invalid framework", async () => {
    const handler = toolsMap["get_framework"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({ framework: "invalid" }, {});
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("audit_item should record item successfully", async () => {
    const handler = toolsMap["audit_item"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Failed access control test"
    }, {});

    expect(response.isError).toBeUndefined();
    const data = JSON.parse(response.content[0].text);
    expect(data.recorded.itemId).toBe("A01");
    expect(data.recorded.status).toBe("fail");
  });

  it("audit_item should update existing item", async () => {
    const handler = toolsMap["audit_item"]?.handler;

    // First record
    await handler({
      sessionId: "test-session-2",
      framework: "nist",
      itemId: "AC-1",
      status: "fail"
    }, {});

    // Update record
    const response = await handler({
      sessionId: "test-session-2",
      framework: "nist",
      itemId: "AC-1",
      status: "pass",
      notes: "Fixed"
    }, {});

    const data = JSON.parse(response.content[0].text);
    expect(data.recorded.status).toBe("pass");
  });

  it("audit_item should error on invalid item", async () => {
    const handler = toolsMap["audit_item"]?.handler;

    const response = await handler({
      sessionId: "test-session-3",
      framework: "owasp",
      itemId: "INVALID-ITEM",
      status: "pass"
    }, {});

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("generate_report should handle missing session", async () => {
    const handler = toolsMap["generate_report"]?.handler;
    const response = await handler({ sessionId: "non-existent", format: "json" }, {});
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("generate_report should generate json report correctly", async () => {
    const auditHandler = toolsMap["audit_item"]?.handler;
    await auditHandler({ sessionId: "report-json", framework: "owasp", itemId: "A01", status: "pass" }, {});

    const handler = toolsMap["generate_report"]?.handler;
    const response = await handler({ sessionId: "report-json", format: "json" }, {});

    expect(response.isError).toBeUndefined();
    const data = JSON.parse(response.content[0].text);
    expect(data.score).toBe("100%");
    expect(data.summary.passed).toBe(1);
  });

  it("generate_report should generate markdown report correctly", async () => {
    const auditHandler = toolsMap["audit_item"]?.handler;
    await auditHandler({ sessionId: "report-md", framework: "owasp", itemId: "A01", status: "fail", notes: "Bad" }, {});

    const handler = toolsMap["generate_report"]?.handler;
    const response = await handler({ sessionId: "report-md", format: "markdown" }, {});

    expect(response.isError).toBeUndefined();
    expect(response.content[0].text).toContain("## 🚨 Critical Findings");
    expect(response.content[0].text).toContain("Score:** 0%");
  });

  it("generate_report should generate HTML report correctly", async () => {
    const auditHandler = toolsMap["audit_item"]?.handler;
    await auditHandler({ sessionId: "report-html", framework: "owasp", itemId: "A01", status: "skip" }, {});

    const handler = toolsMap["generate_report"]?.handler;
    const response = await handler({ sessionId: "report-html", format: "html" }, {});

    expect(response.isError).toBeUndefined();
    expect(response.content[0].text).toContain("<!DOCTYPE html>");
    expect(response.content[0].text).toContain("0%");
  });

  it("get_risk_summary should group risks correctly", async () => {
    const handler = toolsMap["get_risk_summary"]?.handler;
    const response = await handler({ framework: "owasp" }, {});

    const data = JSON.parse(response.content[0].text);
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
  });

  it("search_controls should find controls by keyword", async () => {
    const handler = toolsMap["search_controls"]?.handler;
    const response = await handler({ query: "injection", framework: "all" }, {});

    const data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results["OWASP Top 10"]).toBeDefined();
  });

  it("search_controls should find controls by keyword in specific framework", async () => {
    const handler = toolsMap["search_controls"]?.handler;
    const response = await handler({ query: "injection", framework: "owasp" }, {});

    const data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(data.results).length).toBe(1);
    expect(data.results["OWASP Top 10"]).toBeDefined();
  });

  it("cve_lookup should fetch CVE details successfully", async () => {
    const mockData = { id: "CVE-2021-44228", description: "Log4j vulnerability" };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockData
    });

    const handler = toolsMap["cve_lookup"]?.handler;
    const response = await handler({ cve_id: "CVE-2021-44228" }, {});

    expect(response.isError).toBeUndefined();
    const data = JSON.parse(response.content[0].text);
    expect(data.id).toBe("CVE-2021-44228");
  });

  it("cve_lookup should handle 404 correctly", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404
    });

    const handler = toolsMap["cve_lookup"]?.handler;
    const response = await handler({ cve_id: "CVE-UNKNOWN" }, {});

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("cve_lookup should handle other errors correctly", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

    const handler = toolsMap["cve_lookup"]?.handler;
    const response = await handler({ cve_id: "CVE-ERROR" }, {});

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Network Error");
  });
});