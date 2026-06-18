import { describe, it, expect, beforeEach, vi } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// @ts-ignore - access internal registered tools for direct testing
const toolsMap = server._registeredTools || server.registeredTools;

describe("MCP Server Tools", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
  });

  it("should list frameworks", async () => {
    const list_frameworks = toolsMap["list_frameworks"];
    expect(list_frameworks).toBeDefined();

    const response = await list_frameworks.handler({});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);

    expect(data.frameworks).toHaveLength(Object.keys(FRAMEWORKS).length);
    expect(data.frameworks[0]).toHaveProperty("id");
    expect(data.frameworks[0]).toHaveProperty("name");
  });

  it("should get a specific framework", async () => {
    const get_framework = toolsMap["get_framework"];

    const response = await get_framework.handler({ framework: "owasp" });
    const data = JSON.parse(response.content[0].text);

    expect(data.name).toBe("OWASP Top 10");
    expect(data.items.length).toBeGreaterThan(0);
  });

  it("should return error for invalid framework in get_framework", async () => {
    const get_framework = toolsMap["get_framework"];

    const response = await get_framework.handler({ framework: "invalid" as any });
    expect(response.isError).toBe(true);
  });

  it("should audit an item and track session", async () => {
    const audit_item = toolsMap["audit_item"];

    const response1 = await audit_item.handler({
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "Looks good"
    });

    const data1 = JSON.parse(response1.content[0].text);
    expect(data1.recorded.status).toBe("pass");
    expect(data1.sessionProgress).toContain("1 /");
  });

  it("should return error for invalid audit item", async () => {
    const audit_item = toolsMap["audit_item"];

    const response = await audit_item.handler({
      sessionId: "test-session-2",
      framework: "owasp",
      itemId: "INVALID-ITEM",
      status: "pass"
    });

    expect(response.isError).toBe(true);
  });

  it("should generate report for a session", async () => {
    const audit_item = toolsMap["audit_item"];
    const generate_report = toolsMap["generate_report"];

    await audit_item.handler({
      sessionId: "test-session-3",
      framework: "owasp",
      itemId: "A01",
      status: "pass"
    });

    const jsonReport = await generate_report.handler({ sessionId: "test-session-3", format: "json" });
    const data = JSON.parse(jsonReport.content[0].text);
    expect(data.score).toBe("100%");

    const markdownReport = await generate_report.handler({ sessionId: "test-session-3", format: "markdown" });
    expect(markdownReport.content[0].text).toContain("## OWASP Top 10");

    const htmlReport = await generate_report.handler({ sessionId: "test-session-3", format: "html" });
    expect(htmlReport.content[0].text).toContain("<!DOCTYPE html>");
  });

  it("should return error for generating report of non-existent session", async () => {
    const generate_report = toolsMap["generate_report"];
    const response = await generate_report.handler({ sessionId: "invalid-session", format: "json" });
    expect(response.isError).toBe(true);
  });

  it("should return risk summary", async () => {
    const get_risk_summary = toolsMap["get_risk_summary"];

    const response = await get_risk_summary.handler({ framework: "owasp" });
    const data = JSON.parse(response.content[0].text);

    expect(data.framework).toBe("OWASP Top 10");
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("should search controls", async () => {
    const search_controls = toolsMap["search_controls"];

    const response = await search_controls.handler({ query: "injection", framework: "all" });
    const data = JSON.parse(response.content[0].text);

    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results["OWASP Top 10"]).toBeDefined();
  });

  it("should search controls within specific framework", async () => {
    const search_controls = toolsMap["search_controls"];

    const response = await search_controls.handler({ query: "access control", framework: "nist" });
    const data = JSON.parse(response.content[0].text);

    expect(data.results["NIST SP 800-53"]).toBeDefined();
    expect(data.results["OWASP Top 10"]).toBeUndefined();
  });

  describe("cve_lookup tool", () => {
    it("should fetch and parse a CVE successfully", async () => {
      const cve_lookup = toolsMap["cve_lookup"];
      const mockResponse = {
        cveMetadata: {
          state: "PUBLISHED",
          datePublished: "2021-12-10T00:00:00",
          dateUpdated: "2021-12-15T00:00:00"
        },
        containers: {
          cna: {
            title: "Log4j Vulnerability",
            descriptions: [{ value: "A critical vulnerability in Log4j." }],
            metrics: [{ cvssV3_1: { baseScore: 10.0, baseSeverity: "CRITICAL" } }]
          }
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const response = await cve_lookup.handler({ cveId: "CVE-2021-44228" });
      const data = JSON.parse(response.content[0].text);

      expect(data.id).toBe("CVE-2021-44228");
      expect(data.title).toBe("Log4j Vulnerability");
      expect(data.description).toBe("A critical vulnerability in Log4j.");
      expect(data.cvss.score).toBe(10.0);
      expect(data.cvss.severity).toBe("CRITICAL");
      expect(data.status).toBe("PUBLISHED");
    });

    it("should return an error when CVE is not found", async () => {
      const cve_lookup = toolsMap["cve_lookup"];
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      });

      const response = await cve_lookup.handler({ cveId: "CVE-9999-9999" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("CVE 'CVE-9999-9999' not found.");
    });

    it("should return an error on fetch failure", async () => {
      const cve_lookup = toolsMap["cve_lookup"];
      global.fetch = vi.fn().mockRejectedValue(new Error("Network error"));

      const response = await cve_lookup.handler({ cveId: "CVE-2021-44228" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error fetching CVE 'CVE-2021-44228': Network error");
    });
  });
});
