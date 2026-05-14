import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from "../src/index.js";
import { FRAMEWORKS } from "../src/frameworks.js";

// Mock transport and connect
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class StdioServerTransport {}
  };
});

describe("security-audit-mcp server tools", () => {
  const tools = (server as any)._registeredTools || (server as any).tools;

  beforeEach(() => {
    // We would clear sessions map here if it was exported,
    // but since it's internal we'll use unique session IDs for tests.
  });

  it("should have list_frameworks tool", async () => {
    const listFrameworks = tools["list_frameworks"] || tools.get("list_frameworks");
    expect(listFrameworks).toBeDefined();

    // We can't easily invoke without proper mock setup in some SDK versions,
    // but we can try handling via internal handler if available or just check existence.
    // In @modelcontextprotocol/sdk 1.0.0, tools are often registered internally.
    const result = await listFrameworks.handler({});
    expect(result.content[0].text).toContain("OWASP Top 10");
    expect(result.content[0].text).toContain("PCI-DSS");
  });

  it("should have get_framework tool", async () => {
    const getFramework = tools["get_framework"] || tools.get("get_framework");
    expect(getFramework).toBeDefined();

    const result = await getFramework.handler({ framework: "owasp" });
    expect(result.content[0].text).toContain("A01");
  });

  it("should return error for invalid framework in get_framework", async () => {
    const getFramework = tools["get_framework"] || tools.get("get_framework");
    const result = await getFramework.handler({ framework: "invalid" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("should have audit_item tool", async () => {
    const auditItem = tools["audit_item"] || tools.get("audit_item");
    expect(auditItem).toBeDefined();

    const result = await auditItem.handler({
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Failed access control"
    });
    expect(result.content[0].text).toContain("Fail");
    expect(result.content[0].text).toContain("recorded");
  });

  it("should generate report correctly in markdown", async () => {
    const auditItem = tools["audit_item"] || tools.get("audit_item");
    await auditItem.handler({ sessionId: "test-session-2", framework: "owasp", itemId: "A01", status: "pass" });
    await auditItem.handler({ sessionId: "test-session-2", framework: "owasp", itemId: "A02", status: "fail", notes: "bad crypto" });

    const generateReport = tools["generate_report"] || tools.get("generate_report");
    const result = await generateReport.handler({ sessionId: "test-session-2", format: "markdown" });

    expect(result.content[0].text).toContain("Security Audit Report");
    expect(result.content[0].text).toContain("**Passed:** 1");
    expect(result.content[0].text).toContain("**Failed:** 1");
    expect(result.content[0].text).toContain("bad crypto");
  });

  it("should have get_risk_summary tool", async () => {
    const getRiskSummary = tools["get_risk_summary"] || tools.get("get_risk_summary");
    const result = await getRiskSummary.handler({ framework: "owasp" });
    expect(result.content[0].text).toContain("CRITICAL");
  });

  it("should have search_controls tool", async () => {
    const searchControls = tools["search_controls"] || tools.get("search_controls");
    const result = await searchControls.handler({ query: "injection", framework: "all" });
    expect(result.content[0].text).toContain("A03");
  });

  it("should have cve_lookup tool", async () => {
    // Mock global fetch for CVE API
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "CVE-2021-44228", description: "Log4j" })
    });

    const cveLookup = tools["cve_lookup"] || tools.get("cve_lookup");
    const result = await cveLookup.handler({ cveId: "CVE-2021-44228" });
    expect(result.content[0].text).toContain("CVE-2021-44228");
    expect(result.content[0].text).toContain("Log4j");
  });
});
