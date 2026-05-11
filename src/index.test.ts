import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Ensure tests use the internal registered tools.
const getTool = (name: string) => {
  const tools = (server as any)._registeredTools;
  if (!tools || !tools[name]) {
    throw new Error(`Tool \${name} not found`);
  }
  return tools[name];
};

describe("security-audit-mcp server", () => {
  beforeEach(() => {
    // We can clear or reset if needed, but session state might carry over.
  });

  describe("list_frameworks tool", () => {
    it("should list all available frameworks", async () => {
      const tool = getTool("list_frameworks");
      const result = await tool.handler({});

      expect(result.isError).toBeUndefined();
      expect(result.content.length).toBe(1);

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks).toBeDefined();
      expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    });
  });

  describe("get_framework tool", () => {
    it("should return the framework details for a known framework", async () => {
      const tool = getTool("get_framework");
      const result = await tool.handler({ framework: "owasp" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe("OWASP Top 10");
    });

    it("should return an error for an unknown framework", async () => {
      const tool = getTool("get_framework");
      const result = await tool.handler({ framework: "unknown" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Framework 'unknown' not found.");
    });
  });

  describe("audit_item tool", () => {
    it("should record a pass result", async () => {
      const tool = getTool("audit_item");
      const result = await tool.handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.status).toBe("pass");
      expect(parsed.recorded.itemId).toBe("A01");
    });

    it("should return an error for unknown items", async () => {
      const tool = getTool("audit_item");
      const result = await tool.handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "XYZ",
        status: "pass"
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Item 'XYZ' not found");
    });
  });

  describe("generate_report tool", () => {
    beforeEach(async () => {
      // Seed a session
      const auditTool = getTool("audit_item");
      await auditTool.handler({
        sessionId: "report-session-1",
        framework: "nist",
        itemId: "AC-1",
        status: "fail",
        notes: "Missing policy"
      });
    });

    it("should return error for unknown session", async () => {
      const tool = getTool("generate_report");
      const result = await tool.handler({ sessionId: "unknown", format: "json" });

      expect(result.isError).toBe(true);
    });

    it("should generate a json report", async () => {
      const tool = getTool("generate_report");
      const result = await tool.handler({ sessionId: "report-session-1", format: "json" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.session).toBe("report-session-1");
      expect(parsed.summary.failed).toBe(1);
    });

    it("should generate a markdown report", async () => {
      const tool = getTool("generate_report");
      const result = await tool.handler({ sessionId: "report-session-1", format: "markdown" });

      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("AC-1");
    });

    it("should generate an html report", async () => {
      const tool = getTool("generate_report");
      const result = await tool.handler({ sessionId: "report-session-1", format: "html" });

      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("AC-1");
    });
  });

  describe("get_risk_summary tool", () => {
    it("should summarize risks correctly", async () => {
      const tool = getTool("get_risk_summary");
      const result = await tool.handler({ framework: "iso27001" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.framework).toBe("ISO 27001");
      expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
    });
  });

  describe("search_controls tool", () => {
    it("should find controls across all frameworks", async () => {
      const tool = getTool("search_controls");
      const result = await tool.handler({ query: "authentication", framework: "all" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.query).toBe("authentication");
      expect(parsed.totalMatches).toBeGreaterThan(0);
    });

    it("should filter search by framework", async () => {
      const tool = getTool("search_controls");
      const result = await tool.handler({ query: "access", framework: "nist" });

      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      // We expect results object to only have "NIST SP 800-53" key.
      const keys = Object.keys(parsed.results);
      expect(keys).toEqual(["NIST SP 800-53"]);
    });
  });
});
