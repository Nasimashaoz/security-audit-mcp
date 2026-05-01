import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock StdioServerTransport as required by instructions
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        connect: vi.fn(),
        close: vi.fn(),
      };
    }),
  };
});

import { server } from "../index.js";
import { FRAMEWORKS } from "../frameworks.js";

// Helper to access internal tools map
const tools = (server as any)._registeredTools;

describe("MCP Tools", () => {
  describe("list_frameworks", () => {
    it("should list all frameworks", async () => {
      const handler = tools["list_frameworks"].handler;
      const result = await handler({});
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks).toBeDefined();
      expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    });
  });

  describe("get_framework", () => {
    it("should return the requested framework", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "owasp" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe("OWASP Top 10");
      expect(parsed.items.length).toBeGreaterThan(0);
    });

    it("should fail for invalid framework", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "invalid" });
      expect(result.isError).toBe(true);
    });
  });

  describe("audit_item", () => {
    it("should add a new audit item result", async () => {
      const handler = tools["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Test failure",
      });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.itemId).toBe("A01");
      expect(parsed.recorded.status).toBe("fail");
      expect(parsed.recorded.notes).toBe("Test failure");
    });

    it("should update an existing audit item result", async () => {
      const handler = tools["audit_item"].handler;
      await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
      });

      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.status).toBe("pass");
    });

    it("should fail for invalid item id", async () => {
      const handler = tools["audit_item"].handler;
      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "INVALID",
        status: "pass",
      });
      expect(result.isError).toBe(true);
    });
  });

  describe("generate_report", () => {
    beforeEach(async () => {
      // populate session
      const auditHandler = tools["audit_item"].handler;
      await auditHandler({ sessionId: "report-session", framework: "nist", itemId: "AC-1", status: "pass" });
      await auditHandler({ sessionId: "report-session", framework: "nist", itemId: "AC-2", status: "fail", notes: "bad" });
    });

    it("should generate json report", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "json" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.session).toBe("report-session");
      expect(parsed.summary.passed).toBe(1);
      expect(parsed.summary.failed).toBe(1);
    });

    it("should generate markdown report", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "markdown" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("AC-1");
      expect(result.content[0].text).toContain("AC-2");
    });

    it("should generate html report", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "report-session", format: "html" });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("AC-1");
    });

    it("should fail for unknown session", async () => {
      const handler = tools["generate_report"].handler;
      const result = await handler({ sessionId: "unknown-session", format: "json" });
      expect(result.isError).toBe(true);
    });
  });

  describe("get_risk_summary", () => {
    it("should return risk breakdown for a framework", async () => {
      const handler = tools["get_risk_summary"].handler;
      const result = await handler({ framework: "iso27001" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
      expect(parsed.riskBreakdown.HIGH).toBeDefined();
    });
  });

  describe("search_controls", () => {
    it("should find controls across all frameworks", async () => {
      const handler = tools["search_controls"].handler;
      const result = await handler({ query: "access", framework: "all" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(parsed.results).length).toBeGreaterThan(0);
    });

    it("should find controls in a specific framework", async () => {
      const handler = tools["search_controls"].handler;
      const result = await handler({ query: "access", framework: "owasp" });
      expect(result.isError).toBeUndefined();
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.results["OWASP Top 10"]).toBeDefined();
      expect(parsed.results["NIST SP 800-53"]).toBeUndefined();
    });
  });
});
