import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport so it doesn't run real stdio in tests
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        start: vi.fn(),
        close: vi.fn(),
      };
    }),
  };
});

describe("security-audit-mcp server", () => {
  let tools: any;

  beforeEach(() => {
    // Access internal tools object
    tools = (server as any)._registeredTools;
  });

  it("should have list_frameworks tool", async () => {
    const handler = tools["list_frameworks"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.frameworks.length).toBeGreaterThan(0);
    expect(data.frameworks[0].id).toBe("owasp");
  });

  it("should have get_framework tool", async () => {
    const handler = tools["get_framework"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({ framework: "owasp" }, {});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
  });

  it("should handle get_framework with invalid framework", async () => {
    const handler = tools["get_framework"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({ framework: "invalid_fw" }, {});
    expect(response.isError).toBe(true);
  });

  it("should have audit_item tool", async () => {
    const handler = tools["audit_item"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "LGTM",
    }, {});

    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.recorded.itemId).toBe("A01");
    expect(data.recorded.status).toBe("pass");
  });

  it("should error on audit_item with invalid item", async () => {
    const handler = tools["audit_item"]?.handler;
    const response = await handler({
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "INVALID-ITEM",
      status: "pass",
      notes: "LGTM",
    }, {});
    expect(response.isError).toBe(true);
  });

  it("should have generate_report tool", async () => {
    // First, add an item
    await tools["audit_item"]?.handler({
      sessionId: "test-session-report",
      framework: "nist",
      itemId: "AC-1",
      status: "fail",
      notes: "Missing policy",
    }, {});

    const handler = tools["generate_report"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({
      sessionId: "test-session-report",
      format: "json",
    }, {});

    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.session).toBe("test-session-report");
    expect(data.framework).toBe("NIST SP 800-53");
    expect(data.summary.failed).toBe(1);
  });

  it("should handle generate_report with missing session", async () => {
    const handler = tools["generate_report"]?.handler;
    const response = await handler({
      sessionId: "missing-session",
      format: "json",
    }, {});
    expect(response.isError).toBe(true);
  });

  it("should support markdown format in generate_report", async () => {
    await tools["audit_item"]?.handler({
      sessionId: "test-session-markdown",
      framework: "iso27001",
      itemId: "A.5.1",
      status: "pass",
    }, {});

    const handler = tools["generate_report"]?.handler;
    const response = await handler({
      sessionId: "test-session-markdown",
      format: "markdown",
    }, {});

    expect(response.content[0].type).toBe("text");
    expect(response.content[0].text).toContain("## ISO 27001");
    expect(response.content[0].text).toContain("| A.5.1 |");
  });

  it("should support html format in generate_report", async () => {
    await tools["audit_item"]?.handler({
      sessionId: "test-session-html",
      framework: "iso27001",
      itemId: "A.5.1",
      status: "pass",
    }, {});

    const handler = tools["generate_report"]?.handler;
    const response = await handler({
      sessionId: "test-session-html",
      format: "html",
    }, {});

    expect(response.content[0].type).toBe("text");
    expect(response.content[0].text).toContain("<!DOCTYPE html>");
    expect(response.content[0].text).toContain("ISO 27001");
  });

  it("should have get_risk_summary tool", async () => {
    const handler = tools["get_risk_summary"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({
      framework: "owasp",
    }, {});

    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.framework).toBe("OWASP Top 10");
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("should have search_controls tool", async () => {
    const handler = tools["search_controls"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({
      query: "authentication",
      framework: "all",
    }, {});

    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.query).toBe("authentication");
    expect(data.totalMatches).toBeGreaterThan(0);
  });

  it("should have get_framework tool for pcidss", async () => {
    const handler = tools["get_framework"]?.handler;
    const response = await handler({ framework: "pcidss" }, {});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe("PCI-DSS");
  });

  it("should audit item in soc2", async () => {
    const handler = tools["audit_item"]?.handler;
    const response = await handler({
      sessionId: "test-session-soc2",
      framework: "soc2",
      itemId: "CC1",
      status: "pass",
    }, {});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.recorded.itemId).toBe("CC1");
  });

  it("should have cve_lookup tool", async () => {
    // Mock global fetch
    const originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        cveMetadata: { cveId: "CVE-2021-44228" },
        containers: { cna: { descriptions: [{ value: "Log4j vulnerability" }] } }
      })
    });

    const handler = tools["cve_lookup"]?.handler;
    const response = await handler({ cveId: "CVE-2021-44228" }, {});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.cveId).toBe("CVE-2021-44228");
    expect(data.description).toContain("Log4j");

    // Restore fetch
    global.fetch = originalFetch;
  });

  it("should handle cve_lookup with invalid CVE", async () => {
    // Mock global fetch
    const originalFetch = global.fetch;
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404
    });

    const handler = tools["cve_lookup"]?.handler;
    const response = await handler({ cveId: "CVE-INVALID" }, {});
    expect(response.isError).toBe(true);

    // Restore fetch
    global.fetch = originalFetch;
  });

});
