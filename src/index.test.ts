import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      async start() {}
      async close() {}
    },
  };
});

describe("security-audit-mcp Tools", () => {
  let toolsMap: any;

  beforeEach(() => {
    toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("should have registered all tools", () => {
    expect(toolsMap["list_frameworks"]).toBeDefined();
    expect(toolsMap["get_framework"]).toBeDefined();
    expect(toolsMap["audit_item"]).toBeDefined();
    expect(toolsMap["generate_report"]).toBeDefined();
    expect(toolsMap["get_risk_summary"]).toBeDefined();
    expect(toolsMap["search_controls"]).toBeDefined();
    expect(toolsMap["cve_lookup"]).toBeDefined();
  });

  describe("list_frameworks", () => {
    it("should list all available frameworks", async () => {
      const handler = toolsMap["list_frameworks"].handler;
      const result = await handler({});

      const content = JSON.parse(result.content[0].text);
      expect(content.frameworks).toBeInstanceOf(Array);
      expect(content.frameworks.length).toBeGreaterThan(0);

      const owasp = content.frameworks.find((f: any) => f.id === "owasp");
      expect(owasp).toBeDefined();
      expect(owasp.name).toBe("OWASP Top 10");
    });
  });

  describe("get_framework", () => {
    it("should return the checklist for a specific framework", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "owasp" }, {});

      const content = JSON.parse(result.content[0].text);
      expect(content.name).toBe("OWASP Top 10");
      expect(content.items).toBeInstanceOf(Array);
      expect(content.items.length).toBeGreaterThan(0);
    });

    it("should return an error if framework is not found", async () => {
      const handler = toolsMap["get_framework"].handler;
      const result = await handler({ framework: "nonexistent" }, {});

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item", () => {
    it("should record an audit result successfully", async () => {
      const handler = toolsMap["audit_item"].handler;
      const args = {
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      };

      const result = await handler(args, {});
      const content = JSON.parse(result.content[0].text);

      expect(content.recorded.itemId).toBe("A01");
      expect(content.recorded.status).toBe("pass");
      expect(content.recorded.notes).toBe("Looks good");
    });

    it("should return error for invalid item ID", async () => {
      const handler = toolsMap["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "NONEXISTENT",
        status: "pass"
      }, {});

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found in owasp");
    });
  });

  describe("generate_report", () => {
    beforeEach(async () => {
      // Seed a session
      const handler = toolsMap["audit_item"].handler;
      await handler({ sessionId: "report-session", framework: "owasp", itemId: "A01", status: "pass" }, {});
      await handler({ sessionId: "report-session", framework: "owasp", itemId: "A02", status: "fail", notes: "bad crypto" }, {});
    });

    it("should generate a JSON report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "json" }, {});

      const content = JSON.parse(result.content[0].text);
      expect(content.session).toBe("report-session");
      expect(content.summary.passed).toBe(1);
      expect(content.summary.failed).toBe(1);
      expect(content.score).toBe("50%");
    });

    it("should generate a Markdown report", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "markdown" }, {});

      const text = result.content[0].text;
      expect(text).toContain("# 🔒 Security Audit Report");
      expect(text).toContain("**Passed:** 1 | **Failed:** 1");
    });

    it("should return error for nonexistent session", async () => {
      const handler = toolsMap["generate_report"].handler;
      const result = await handler({ sessionId: "invalid", format: "json" }, {});
      expect(result.isError).toBe(true);
    });
  });

  describe("get_risk_summary", () => {
    it("should group controls by risk level", async () => {
      const handler = toolsMap["get_risk_summary"].handler;
      const result = await handler({ framework: "owasp" }, {});

      const content = JSON.parse(result.content[0].text);
      expect(content.riskBreakdown).toBeDefined();
      expect(content.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(content.riskBreakdown.HIGH.length).toBeGreaterThan(0);
    });
  });

  describe("search_controls", () => {
    it("should find controls matching keyword across all frameworks", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "injection", framework: "all" }, {});

      const content = JSON.parse(result.content[0].text);
      expect(content.totalMatches).toBeGreaterThan(0);
      expect(content.results["OWASP Top 10"]).toBeDefined();
    });

    it("should filter search by specific framework", async () => {
      const handler = toolsMap["search_controls"].handler;
      const result = await handler({ query: "access", framework: "nist" }, {});

      const content = JSON.parse(result.content[0].text);
      expect(content.results["OWASP Top 10"]).toBeUndefined();
      expect(content.results["NIST SP 800-53"]).toBeDefined();
    });
  });

  describe("cve_lookup", () => {
    it("should return CVE details on success", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          cveMetadata: { cveId: "CVE-2021-44228" },
        }),
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" }, {});

      const content = JSON.parse(result.content[0].text);
      expect(content.cveMetadata.cveId).toBe("CVE-2021-44228");
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle 404 not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-INVALID" }, {});

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle fetch errors", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

      const handler = toolsMap["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-2021-44228" }, {});

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Network Error");
    });
  });
});
