import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock the StdioServerTransport since we can't connect real stdio in tests
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class StdioServerTransport {
      constructor() {}
      start() {}
      close() {}
    }
  };
});

describe("security-audit-mcp server tools", () => {
  // @ts-ignore - access internal registered tools registry
  const toolsMap = server._tools || server._registeredTools || server.registeredTools;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2023-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
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

  describe("list_frameworks tool", () => {
    it("should return a list of available frameworks", async () => {
      const handler = toolsMap["list_frameworks"].handler;
      const result = await handler({});
      expect(result.content[0].type).toBe("text");

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks).toBeInstanceOf(Array);
      expect(parsed.frameworks.length).toBeGreaterThan(0);

      // Ensure all frameworks including newly added ones are present
      const frameworkIds = parsed.frameworks.map((fw: any) => fw.id);
      expect(frameworkIds).toContain("owasp");
      expect(frameworkIds).toContain("nist");
      expect(frameworkIds).toContain("iso27001");
      expect(frameworkIds).toContain("pcidss");
      expect(frameworkIds).toContain("soc2");
      expect(frameworkIds).toContain("hipaa");
      expect(frameworkIds).toContain("cis_v8");
      expect(frameworkIds).toContain("gdpr");
    });
  });

  describe("get_framework tool", () => {
    it("should return framework details for a valid framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "owasp" });
      expect(result.content[0].type).toBe("text");

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe("OWASP Top 10");
      expect(parsed.items).toBeInstanceOf(Array);
      expect(parsed.items.length).toBe(10);
    });

    it("should return an error for an invalid framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "invalid" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Framework 'invalid' not found.");
    });
  });

  describe("audit_item tool", () => {
    it("should record a result and start a session if it doesn't exist", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.itemId).toBe("A01");
      expect(parsed.recorded.status).toBe("pass");
      expect(parsed.recorded.notes).toBe("Looks good");
      expect(parsed.sessionProgress).toBe("1 / 10 items audited");
    });

    it("should update an existing result in a session", async () => {
      const handler = toolsMap["audit_item"].handler;

      await handler({
        sessionId: "test-session-2",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });

      const result = await handler({
        sessionId: "test-session-2",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Actually, it failed"
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.status).toBe("fail");
      expect(parsed.recorded.notes).toBe("Actually, it failed");
      expect(parsed.sessionProgress).toBe("1 / 10 items audited");
    });

    it("should return an error for an invalid framework item", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-error",
        framework: "owasp",
        itemId: "INVALID-ITEM",
        status: "pass",
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Item 'INVALID-ITEM' not found in owasp.");
    });
  });

  describe("generate_report tool", () => {
    beforeEach(async () => {
      // Seed a session for reporting
      const auditHandler = toolsMap["audit_item"].handler;
      await auditHandler({ sessionId: "report-session", framework: "owasp", itemId: "A01", status: "pass" });
      await auditHandler({ sessionId: "report-session", framework: "owasp", itemId: "A02", status: "fail", notes: "Bad encryption" });
      await auditHandler({ sessionId: "report-session", framework: "owasp", itemId: "A03", status: "skip" });
    });

    it("should generate a JSON report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "json" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.session).toBe("report-session");
      expect(parsed.score).toBe("33%");
      expect(parsed.summary.passed).toBe(1);
      expect(parsed.summary.failed).toBe(1);
      expect(parsed.summary.skipped).toBe(1);
      expect(parsed.generatedAt).toBe("2023-01-01T00:00:00.000Z");
    });

    it("should generate a markdown report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "markdown" });

      expect(result.isError).toBeUndefined();
      const text = result.content[0].text;
      expect(text).toContain("# 🔒 Security Audit Report");
      expect(text).toContain("**Score:** 33%");
      expect(text).toContain("## 🚨 Critical Findings");
      expect(text).toContain("Bad encryption");
    });

    it("should generate an HTML report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "html" });

      expect(result.isError).toBeUndefined();
      const text = result.content[0].text;
      expect(text).toContain("<!DOCTYPE html>");
      expect(text).toContain("33%");
    });

    it("should return an error if session is not found", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "invalid-session", format: "json" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Session 'invalid-session' not found.");
    });
  });

  describe("get_risk_summary tool", () => {
    it("should summarize risks by severity for a framework", async () => {
      const handler = toolsMap["get_risk_summary"].handler;
      const result = await handler({ framework: "owasp" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.framework).toBe("OWASP Top 10");
      expect(parsed.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
      expect(parsed.riskBreakdown.CRITICAL.length).toBe(3); // A01, A02, A03
      expect(parsed.riskBreakdown.HIGH).toBeInstanceOf(Array);
      expect(parsed.riskBreakdown.HIGH.length).toBe(5); // A04, A05, A06, A07, A10
      expect(parsed.riskBreakdown.MEDIUM).toBeInstanceOf(Array);
      expect(parsed.riskBreakdown.MEDIUM.length).toBe(2); // A08, A09
    });
  });

  describe("search_controls tool", () => {
    it("should search across all frameworks by default", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "encrypt", framework: "all" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(parsed.results["OWASP Top 10"]).toBeDefined(); // A02 Cryptographic Failures description contains encrypt(ed)
      expect(typeof parsed.totalMatches).toBe("number");
    });

    it("should limit search to a specific framework", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "authentication", framework: "owasp" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.results["OWASP Top 10"]).toBeDefined();
      expect(parsed.results["NIST SP 800-53"]).toBeUndefined();
    });
  });

  describe("cve_lookup tool", () => {
    it("should successfully fetch and return CVE data", async () => {
      const mockCveData = {
        cveMetadata: {
          cveId: "CVE-2021-44228",
          state: "PUBLISHED",
          assignerShortName: "Apache",
          datePublished: "2021-12-10T00:00:00Z"
        },
        containers: {
          cna: {
            descriptions: [{ value: "Log4j vulnerability" }],
            metrics: [{ cvssV3_1: { baseScore: 10.0, baseSeverity: "CRITICAL" } }]
          }
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockCveData
      } as any);

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.id).toBe("CVE-2021-44228");
      expect(parsed.description).toBe("Log4j vulnerability");
      expect(parsed.cvssScore).toBe("10");
      expect(parsed.cvssSeverity).toBe("CRITICAL");
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle 404 from MITRE API", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      } as any);

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-9999-99999" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("CVE 'CVE-9999-99999' not found.");
    });

    it("should handle other API errors gracefully", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500
      } as any);

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch CVE data: API error: 500");
    });
  });
});
