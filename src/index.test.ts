import { describe, it, expect, vi, beforeEach } from "vitest";
import { server, sessions } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdIoTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start = vi.fn();
      close = vi.fn();
    },
  };
});

// Mock fetch for cve_lookup
global.fetch = vi.fn();

describe("security-audit-mcp server", () => {
  const tools = (server as any)._registeredTools;

  beforeEach(() => {
    sessions.clear();
    vi.clearAllMocks();
  });

  describe("list_frameworks tool", () => {
    it("should return the list of frameworks", async () => {
      const handler = tools["list_frameworks"].handler;
      const result = await handler({});

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(data.frameworks[0].id).toBe("owasp");
    });
  });

  describe("get_framework tool", () => {
    it("should return a framework by id", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "owasp" });

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items.length).toBeGreaterThan(0);
    });

    it("should return an error for an unknown framework", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "unknown" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item tool", () => {
    it("should record a new audit item", async () => {
      const handler = tools["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Missing checks",
      });

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("fail");

      const session = sessions.get("test-session-1");
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
    });

    it("should update an existing audit item", async () => {
      const handler = tools["audit_item"].handler;
      await handler({
        sessionId: "test-session-2",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
      });
      const result = await handler({
        sessionId: "test-session-2",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Fixed",
      });

      const session = sessions.get("test-session-2");
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].status).toBe("pass");
      expect(session?.results[0].notes).toBe("Fixed");
    });

    it("should return an error for an unknown item id", async () => {
      const handler = tools["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-3",
        framework: "owasp",
        itemId: "UNKNOWN-ID",
        status: "pass",
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("generate_report tool", () => {
    beforeEach(async () => {
      const handler = tools["audit_item"].handler;
      await handler({ sessionId: "rep-session", framework: "owasp", itemId: "A01", status: "pass" });
      await handler({ sessionId: "rep-session", framework: "owasp", itemId: "A02", status: "fail", notes: "bad crypto" });
      await handler({ sessionId: "rep-session", framework: "owasp", itemId: "A03", status: "skip" });
    });

    it("should return error if session not found", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "missing", format: "json" });
      expect(result.isError).toBe(true);
    });

    it("should generate a JSON report", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "rep-session", format: "json" });

      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe("rep-session");
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.summary.skipped).toBe(1);
    });

    it("should generate a Markdown report", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "rep-session", format: "markdown" });

      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("bad crypto");
    });

    it("should generate an HTML report", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "rep-session", format: "html" });

      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("bad crypto");
    });
  });

  describe("get_risk_summary tool", () => {
    it("should return risk breakdown for a framework", async () => {
      const handler = tools["get_risk_summary"].handler;
      const result = await handler({ framework: "owasp" });

      const data = JSON.parse(result.content[0].text);
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
    });
  });

  describe("search_controls tool", () => {
    it("should search controls across all frameworks", async () => {
      const handler = tools["search_controls"].handler;
      const result = await handler({ query: "encryption", framework: "all" });

      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["HIPAA Security Rule"]).toBeDefined();
    });

    it("should search controls within a specific framework", async () => {
      const handler = tools["search_controls"].handler;
      const result = await handler({ query: "injection", framework: "owasp" });

      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
      expect(data.results["NIST SP 800-53"]).toBeUndefined();
    });
  });

  describe("cve_lookup tool", () => {
    it("should fetch and parse a valid CVE", async () => {
      const mockCveData = {
        cveMetadata: {
          cveId: "CVE-2021-44228",
          state: "PUBLISHED",
          datePublished: "2021-12-10T10:00:00.000Z",
          dateUpdated: "2021-12-11T10:00:00.000Z"
        },
        containers: {
          cna: {
            descriptions: [{ lang: "en", value: "Log4j vulnerability description." }],
            metrics: [{ cvssV3_1: { baseScore: 10.0, baseSeverity: "CRITICAL" } }]
          }
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" });

      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe("CVE-2021-44228");
      expect(data.description).toBe("Log4j vulnerability description.");
      expect(data.metrics).toContain("CVSS v3.1: 10 (CRITICAL)");
    });

    it("should handle 404 from MITRE API", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-UNKNOWN" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle other HTTP errors", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-ERROR" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("HTTP 500");
    });

    it("should handle fetch failures", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network Error"));

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-ERROR" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Network Error");
    });

    it("should handle cve with cvssV3_0", async () => {
      const mockCveData = {
        containers: {
          cna: {
            descriptions: [{ lang: "en", value: "v3.0 description." }],
            metrics: [{ cvssV3_0: { baseScore: 9.0, baseSeverity: "HIGH" } }]
          }
        }
      };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-TEST" });

      const data = JSON.parse(result.content[0].text);
      expect(data.metrics).toContain("CVSS v3.0: 9 (HIGH)");
    });

    it("should handle cve with cvssV2_0", async () => {
      const mockCveData = {
        containers: {
          cna: {
            descriptions: [{ lang: "en", value: "v2.0 description." }],
            metrics: [{ cvssV2_0: { baseScore: 7.5 } }]
          }
        }
      };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-TEST" });

      const data = JSON.parse(result.content[0].text);
      expect(data.metrics).toContain("CVSS v2.0: 7.5");
    });

    it("should handle cve with unknown metrics", async () => {
      const mockCveData = {
        containers: {
          cna: {
            descriptions: [{ lang: "en", value: "unknown description." }],
            metrics: [{ unknownMetric: true }]
          }
        }
      };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-TEST" });

      const data = JSON.parse(result.content[0].text);
      expect(data.metrics).toContain("Unknown metrics");
    });
  });

  describe("main function", () => {
    it("should start the server via main()", async () => {
      const { main, server } = await import("./index.js");
      const connectSpy = vi.spyOn(server, "connect").mockResolvedValueOnce(undefined);
      const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

      await main();

      expect(connectSpy).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith("🔐 security-audit-mcp server running on stdio");

      consoleSpy.mockRestore();
    });
  });
});
