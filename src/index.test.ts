import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport, otherwise testing fails if index tries to start up real transport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: class {
    start = vi.fn();
    close = vi.fn();
  },
}));

describe("security-audit-mcp server tools", () => {
  let toolsMap: any;

  beforeEach(() => {
    // Access the registered tools directly to test the handlers
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2023-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should list frameworks correctly", async () => {
    const listFrameworksHandler = toolsMap["list_frameworks"]?.handler;
    expect(listFrameworksHandler).toBeDefined();

    const response = await listFrameworksHandler({}, {});
    expect(response).toBeDefined();
    expect(response.content[0].type).toBe("text");

    const content = JSON.parse(response.content[0].text);
    expect(content.frameworks).toBeDefined();

    // Check if new frameworks are included
    const frameworks = content.frameworks;
    expect(frameworks.some((f: any) => f.id === "pci-dss")).toBe(true);
    expect(frameworks.some((f: any) => f.id === "gdpr")).toBe(true);
  });

  it("should get a specific framework checklist", async () => {
    const getFrameworkHandler = toolsMap["get_framework"]?.handler;
    expect(getFrameworkHandler).toBeDefined();

    const response = await getFrameworkHandler({ framework: "owasp" }, {});
    expect(response).toBeDefined();

    const content = JSON.parse(response.content[0].text);
    expect(content.name).toBe("OWASP Top 10");
    expect(content.items.length).toBeGreaterThan(0);
  });

  it("should return an error when getting an invalid framework", async () => {
    const getFrameworkHandler = toolsMap["get_framework"]?.handler;
    expect(getFrameworkHandler).toBeDefined();

    const response = await getFrameworkHandler({ framework: "invalid_framework" }, {});
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Framework 'invalid_framework' not found.");
  });

  it("should audit an item and update session", async () => {
    const auditItemHandler = toolsMap["audit_item"]?.handler;
    expect(auditItemHandler).toBeDefined();

    const response = await auditItemHandler({
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "All good"
    }, {});

    expect(response).toBeDefined();
    const content = JSON.parse(response.content[0].text);
    expect(content.recorded.itemId).toBe("A01");
    expect(content.recorded.status).toBe("pass");
    expect(content.sessionProgress).toBeDefined();

    // Test updating an existing item
    const updateResponse = await auditItemHandler({
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Failed on review"
    }, {});
    const updateContent = JSON.parse(updateResponse.content[0].text);
    expect(updateContent.recorded.status).toBe("fail");
  });

  it("should return error when auditing an invalid item", async () => {
    const auditItemHandler = toolsMap["audit_item"]?.handler;
    const response = await auditItemHandler({
      sessionId: "test-session-invalid",
      framework: "owasp",
      itemId: "INVALID-ITEM",
      status: "pass"
    }, {});
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Item 'INVALID-ITEM' not found");
  });

  it("should generate a report in json format", async () => {
    // First we must add data to the session
    const auditItemHandler = toolsMap["audit_item"]?.handler;
    await auditItemHandler({
      sessionId: "test-session-report",
      framework: "owasp",
      itemId: "A01",
      status: "pass"
    }, {});

    const generateReportHandler = toolsMap["generate_report"]?.handler;
    expect(generateReportHandler).toBeDefined();

    const response = await generateReportHandler({
      sessionId: "test-session-report",
      format: "json"
    }, {});

    expect(response).toBeDefined();
    const content = JSON.parse(response.content[0].text);
    expect(content.session).toBe("test-session-report");
    expect(content.score).toBe("100%"); // 1 item, passed
    expect(content.summary.passed).toBe(1);
    expect(content.generatedAt).toBe("2023-01-01T00:00:00.000Z");
  });

  it("should generate a report in markdown format", async () => {
    const generateReportHandler = toolsMap["generate_report"]?.handler;
    const response = await generateReportHandler({
      sessionId: "test-session-report",
      format: "markdown"
    }, {});

    expect(response).toBeDefined();
    const content = response.content[0].text;
    expect(content).toContain("# 🔒 Security Audit Report");
    expect(content).toContain("A01");
  });

  it("should generate a report in html format", async () => {
    const generateReportHandler = toolsMap["generate_report"]?.handler;
    const response = await generateReportHandler({
      sessionId: "test-session-report",
      format: "html"
    }, {});

    expect(response).toBeDefined();
    const content = response.content[0].text;
    expect(content).toContain("<!DOCTYPE html>");
    expect(content).toContain("A01");
  });

  it("should return error when generating report for missing session", async () => {
    const generateReportHandler = toolsMap["generate_report"]?.handler;
    const response = await generateReportHandler({
      sessionId: "missing-session",
      format: "json"
    }, {});
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Session 'missing-session' not found");
  });

  it("should generate a risk summary", async () => {
    const getRiskSummaryHandler = toolsMap["get_risk_summary"]?.handler;
    expect(getRiskSummaryHandler).toBeDefined();

    const response = await getRiskSummaryHandler({ framework: "owasp" }, {});
    expect(response).toBeDefined();
    const content = JSON.parse(response.content[0].text);
    expect(content.framework).toBe("OWASP Top 10");
    expect(content.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(content.riskBreakdown.HIGH.length).toBeGreaterThan(0);
  });

  it("should search controls across all frameworks", async () => {
    const searchControlsHandler = toolsMap["search_controls"]?.handler;
    expect(searchControlsHandler).toBeDefined();

    const response = await searchControlsHandler({ query: "encrypt", framework: "all" }, {});
    expect(response).toBeDefined();
    const content = JSON.parse(response.content[0].text);
    expect(content.query).toBe("encrypt");
    expect(content.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(content.results).length).toBeGreaterThan(0);
  });

  it("should search controls within a specific framework", async () => {
    const searchControlsHandler = toolsMap["search_controls"]?.handler;
    const response = await searchControlsHandler({ query: "encrypt", framework: "owasp" }, {});
    expect(response).toBeDefined();
    const content = JSON.parse(response.content[0].text);
    expect(content.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(content.results)).toEqual(["OWASP Top 10"]);
  });

  describe("cve_lookup tool", () => {
    it("should successfully lookup a CVE", async () => {
      const cveLookupHandler = toolsMap["cve_lookup"]?.handler;
      expect(cveLookupHandler).toBeDefined();

      const mockResponse = {
        cveMetadata: { cveId: "CVE-2021-44228" },
        containers: { cna: { descriptions: [{ value: "Log4j vulnerability" }] } }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      const response = await cveLookupHandler({ cveId: "CVE-2021-44228" }, {});
      expect(response).toBeDefined();
      const content = JSON.parse(response.content[0].text);
      expect(content).toEqual(mockResponse);
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle 404 CVE not found", async () => {
      const cveLookupHandler = toolsMap["cve_lookup"]?.handler;
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      const response = await cveLookupHandler({ cveId: "CVE-INVALID" }, {});
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("CVE 'CVE-INVALID' not found.");
    });

    it("should handle other fetch errors", async () => {
      const cveLookupHandler = toolsMap["cve_lookup"]?.handler;
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error"
      });

      const response = await cveLookupHandler({ cveId: "CVE-ERROR" }, {});
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Failed to fetch CVE data: Internal Server Error");
    });

    it("should handle network errors gracefully", async () => {
      const cveLookupHandler = toolsMap["cve_lookup"]?.handler;
      global.fetch = vi.fn().mockRejectedValue(new Error("Network failure"));

      const response = await cveLookupHandler({ cveId: "CVE-NETWORK" }, {});
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error fetching CVE 'CVE-NETWORK': Network failure");
    });
  });
});
