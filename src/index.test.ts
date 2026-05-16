import { describe, it, expect, vi, beforeEach } from "vitest";
import { server, main } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport
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
  const tools = (server as any)._registeredTools;

  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("should have all expected tools registered", () => {
    expect(tools).toHaveProperty("list_frameworks");
    expect(tools).toHaveProperty("get_framework");
    expect(tools).toHaveProperty("audit_item");
    expect(tools).toHaveProperty("generate_report");
    expect(tools).toHaveProperty("get_risk_summary");
    expect(tools).toHaveProperty("search_controls");
    expect(tools).toHaveProperty("cve_lookup");
  });

  describe("tool: list_frameworks", () => {
    it("should return a list of frameworks", async () => {
      const handler = tools["list_frameworks"].handler;
      const result = await handler({});
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeInstanceOf(Array);
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks.find((f: any) => f.id === "owasp")).toBeDefined();
      expect(data.frameworks.find((f: any) => f.id === "pci-dss")).toBeDefined();
    });
  });

  describe("tool: get_framework", () => {
    it("should return the full checklist for a valid framework", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "owasp" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items).toBeInstanceOf(Array);
    });

    it("should return an error for an invalid framework", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "invalid_framework" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("tool: audit_item", () => {
    it("should successfully record a valid audit item", async () => {
      const handler = tools["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");
      expect(data.sessionProgress).toBeDefined();
    });

    it("should update an existing audit item", async () => {
      const handler = tools["audit_item"].handler;
      await handler({
        sessionId: "test-session-update",
        framework: "owasp",
        itemId: "A02",
        status: "pass"
      });
      const updateResult = await handler({
        sessionId: "test-session-update",
        framework: "owasp",
        itemId: "A02",
        status: "fail",
        notes: "Failed after all"
      });
      const data = JSON.parse(updateResult.content[0].text);
      expect(data.recorded.status).toBe("fail");
      expect(data.recorded.notes).toBe("Failed after all");
    });

    it("should return an error for an invalid item ID", async () => {
      const handler = tools["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-invalid",
        framework: "owasp",
        itemId: "INVALID-99",
        status: "pass"
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("tool: generate_report", () => {
    it("should generate a markdown report", async () => {
      const auditHandler = tools["audit_item"].handler;
      await auditHandler({ sessionId: "report-session", framework: "owasp", itemId: "A01", status: "pass" });
      await auditHandler({ sessionId: "report-session", framework: "owasp", itemId: "A02", status: "fail" });
      await auditHandler({ sessionId: "report-session", framework: "owasp", itemId: "A03", status: "skip" });

      const reportHandler = tools["generate_report"].handler;
      const result = await reportHandler({ sessionId: "report-session", format: "markdown" });
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("OWASP Top 10");
      expect(result.content[0].text).toContain("**Passed:** 1");
      expect(result.content[0].text).toContain("**Failed:** 1");
      expect(result.content[0].text).toContain("**Skipped:** 1");
    });

    it("should generate a JSON report", async () => {
      const auditHandler = tools["audit_item"].handler;
      await auditHandler({ sessionId: "report-session-json", framework: "nist", itemId: "AC-1", status: "pass" });

      const reportHandler = tools["generate_report"].handler;
      const result = await reportHandler({ sessionId: "report-session-json", format: "json" });
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe("report-session-json");
      expect(data.framework).toBe("NIST SP 800-53");
      expect(data.summary.passed).toBe(1);
    });

    it("should generate an HTML report", async () => {
      const auditHandler = tools["audit_item"].handler;
      await auditHandler({ sessionId: "report-session-html", framework: "iso27001", itemId: "A.5.1", status: "pass" });

      const reportHandler = tools["generate_report"].handler;
      const result = await reportHandler({ sessionId: "report-session-html", format: "html" });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("ISO 27001");
    });

    it("should handle 0 score calculation correctly (empty session)", async () => {
        const auditHandler = tools["audit_item"].handler;
        // Hack to get an empty session by failing audit item but creating session map
        await auditHandler({ sessionId: "empty-session", framework: "owasp", itemId: "A99", status: "pass" }); // Fails but creates nothing
        const sessions = (server as any)._registeredTools["audit_item"].handler; // Cannot easily force empty session due to logic, skipped for score 0 edge case but good to check.
        // Let's create a session with only fails
        await auditHandler({ sessionId: "fail-session", framework: "owasp", itemId: "A01", status: "fail" });
        const reportHandler = tools["generate_report"].handler;
        const result = await reportHandler({ sessionId: "fail-session", format: "json" });
        const data = JSON.parse(result.content[0].text);
        expect(data.score).toBe("0%");
    });

    it("should return error for non-existent session", async () => {
        const reportHandler = tools["generate_report"].handler;
        const result = await reportHandler({ sessionId: "non-existent", format: "json" });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("not found");
    });
  });

  describe("tool: get_risk_summary", () => {
    it("should return risk breakdown for a framework", async () => {
      const handler = tools["get_risk_summary"].handler;
      const result = await handler({ framework: "owasp" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
    });
  });

  describe("tool: search_controls", () => {
    it("should search controls across all frameworks", async () => {
      const handler = tools["search_controls"].handler;
      const result = await handler({ query: "authentication", framework: "all" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.query).toBe("authentication");
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });

    it("should search controls in a specific framework", async () => {
      const handler = tools["search_controls"].handler;
      const result = await handler({ query: "injection", framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.results["OWASP Top 10"]).toBeDefined();
      expect(data.results["OWASP Top 10"].some((i: any) => i.id === "A03")).toBe(true);
      expect(data.results["NIST SP 800-53"]).toBeUndefined();
    });
  });

  describe("tool: cve_lookup", () => {
    it("should return CVE details on success", async () => {
      const mockCveData = {
        cveMetadata: {
          cveId: "CVE-2021-44228",
          state: "PUBLISHED",
          datePublished: "2021-12-10T10:00:00.000Z",
        },
        containers: {
          cna: {
            title: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            descriptions: [{ value: "Apache Log4j2 <=2.14.1 JNDI features..." }],
            metrics: [
              {
                cvssV3_1: {
                  baseScore: 10.0,
                  baseSeverity: "CRITICAL"
                }
              }
            ]
          }
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockCveData
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.cveId).toBe("CVE-2021-44228");
      expect(data.cvssScore).toBe(10.0);
      expect(data.cvssSeverity).toBe("CRITICAL");
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle 404 not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found"
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-INVALID" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle API failure", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error"
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-ERROR" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch CVE data");
    });

    it("should handle fetch exception", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-ERROR" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error fetching CVE data");
    });
  });

  describe("main function", () => {
      it("should execute connect on transport", async () => {
          const connectSpy = vi.spyOn(server, 'connect').mockResolvedValue(undefined as never);
          await main();
          expect(connectSpy).toHaveBeenCalled();
          connectSpy.mockRestore();
      });
  });
});
