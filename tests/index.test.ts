import { describe, it, expect, vi, beforeEach } from "vitest";
import { server, sessions } from "../src/index.js";

// Mock fetch globally for CVE lookups
global.fetch = vi.fn();

describe("MCP Server Tools", () => {
  let tools: Record<string, any>;

  beforeEach(() => {
    // Clear sessions
    sessions.clear();
    // Access registered tools
    tools = (server as any)._registeredTools;
    vi.resetAllMocks();
  });

  it("should have all expected tools registered", () => {
    expect(tools).toBeDefined();
    expect(tools["list_frameworks"]).toBeDefined();
    expect(tools["get_framework"]).toBeDefined();
    expect(tools["audit_item"]).toBeDefined();
    expect(tools["generate_report"]).toBeDefined();
    expect(tools["get_risk_summary"]).toBeDefined();
    expect(tools["search_controls"]).toBeDefined();
    expect(tools["cve_lookup"]).toBeDefined();
  });

  describe("list_frameworks", () => {
    it("should return a list of frameworks", async () => {
      const response = await tools["list_frameworks"].handler({});
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(Array.isArray(data.frameworks)).toBe(true);
      expect(data.frameworks.some((fw: any) => fw.id === "owasp")).toBe(true);
      expect(data.frameworks.some((fw: any) => fw.id === "gdpr")).toBe(true);
    });
  });

  describe("get_framework", () => {
    it("should return framework details for a valid framework", async () => {
      const response = await tools["get_framework"].handler({ framework: "owasp" }, {});
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items).toBeDefined();
      expect(Array.isArray(data.items)).toBe(true);
    });

    it("should handle missing framework properly (though zod might catch this first)", async () => {
      const response = await tools["get_framework"].handler({ framework: "nonexistent" }, {});
      expect(response.isError).toBe(true);
    });
  });

  describe("audit_item", () => {
    it("should record an audit result", async () => {
      const args = {
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      };
      const response = await tools["audit_item"].handler(args, {});
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");

      // Verify session was updated
      const session = sessions.get("test-session-1");
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
    });

    it("should return error for invalid item id", async () => {
      const args = {
        sessionId: "test-session-2",
        framework: "owasp",
        itemId: "INVALID-ID",
        status: "pass",
      };
      const response = await tools["audit_item"].handler(args, {});
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("generate_report", () => {
    it("should return an error for non-existent session", async () => {
      const response = await tools["generate_report"].handler({ sessionId: "does-not-exist", format: "json" }, {});
      expect(response.isError).toBe(true);
    });

    it("should generate a JSON report correctly", async () => {
      await tools["audit_item"].handler({
        sessionId: "report-session",
        framework: "owasp",
        itemId: "A01",
        status: "pass"
      }, {});

      const response = await tools["generate_report"].handler({ sessionId: "report-session", format: "json" }, {});
      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe("report-session");
      expect(data.summary.passed).toBe(1);
    });

    it("should generate a markdown report correctly", async () => {
      await tools["audit_item"].handler({
        sessionId: "report-session-md",
        framework: "owasp",
        itemId: "A02",
        status: "fail",
        notes: "Bad crypto"
      }, {});

      const response = await tools["generate_report"].handler({ sessionId: "report-session-md", format: "markdown" }, {});
      expect(response.content[0].text).toContain("Security Audit Report");
      expect(response.content[0].text).toContain("A02");
      expect(response.content[0].text).toContain("Bad crypto");
    });

    it("should generate an HTML report correctly", async () => {
      await tools["audit_item"].handler({
        sessionId: "report-session-html",
        framework: "owasp",
        itemId: "A03",
        status: "skip"
      }, {});

      const response = await tools["generate_report"].handler({ sessionId: "report-session-html", format: "html" }, {});
      expect(response.content[0].text).toContain("<!DOCTYPE html>");
      expect(response.content[0].text).toContain("A03");
    });
  });

  describe("get_risk_summary", () => {
    it("should return risk summary for a framework", async () => {
      const response = await tools["get_risk_summary"].handler({ framework: "owasp" }, {});
      const data = JSON.parse(response.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(data.riskBreakdown.HIGH).toBeDefined();
    });
  });

  describe("search_controls", () => {
    it("should search controls across all frameworks", async () => {
      const response = await tools["search_controls"].handler({ query: "encryption", framework: "all" }, {});
      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["PCI-DSS"]).toBeDefined(); // Use PCI-DSS which has "encryption" in the description
    });

    it("should search controls within a specific framework", async () => {
      const response = await tools["search_controls"].handler({ query: "injection", framework: "owasp" }, {});
      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });
  });

  describe("cve_lookup", () => {
    it("should return CVE details on successful lookup", async () => {
      const mockCveData = {
        containers: { cna: { title: "Test CVE" } }
      };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockCveData
      });

      const response = await tools["cve_lookup"].handler({ cveId: "CVE-2021-44228" }, {});
      expect(response.isError).toBeUndefined();
      const data = JSON.parse(response.content[0].text);
      expect(data.containers.cna.title).toBe("Test CVE");
    });

    it("should handle 404 correctly", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      const response = await tools["cve_lookup"].handler({ cveId: "CVE-DOES-NOT-EXIST" }, {});
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it("should handle API errors correctly", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500
      });

      const response = await tools["cve_lookup"].handler({ cveId: "CVE-ERROR" }, {});
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error looking up CVE");
    });

    it("should handle network errors correctly", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network failure"));

      const response = await tools["cve_lookup"].handler({ cveId: "CVE-NETWORK" }, {});
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Network failure");
    });
  });
});
