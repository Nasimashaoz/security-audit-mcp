import { describe, it, expect, vi } from "vitest";
import { server } from "../src/index.js";
import { FRAMEWORKS } from "../src/frameworks.js";

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

describe("MCP Tools", () => {
  const tools = (server as any)._registeredTools;

  const getToolHandler = (name: string) => {
    return tools[name]?.handler;
  };

  it("should have all tools registered", () => {
    expect(Object.keys(tools).length).toBe(6);
    expect(Object.keys(tools)).toEqual([
      "list_frameworks",
      "get_framework",
      "audit_item",
      "generate_report",
      "get_risk_summary",
      "search_controls",
    ]);
  });

  describe("list_frameworks", () => {
    it("should list all available frameworks", async () => {
      const handler = getToolHandler("list_frameworks");
      const result = await handler({});

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(data.frameworks.map((f: any) => f.id)).toContain("owasp");
      expect(data.frameworks.map((f: any) => f.id)).toContain("pcidss");
    });
  });

  describe("get_framework", () => {
    it("should return framework details for valid id", async () => {
      const handler = getToolHandler("get_framework");
      const result = await handler({ framework: "owasp" });

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items.length).toBeGreaterThan(0);
    });

    it("should return error for invalid framework id", async () => {
      const handler = getToolHandler("get_framework");
      // The zod schema might catch this earlier in the real SDK, but testing internal handler logic
      const result = await handler({ framework: "invalid_framework" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item & generate_report", () => {
    const sessionId = "test-session-123";

    it("should return error for invalid item id", async () => {
      const handler = getToolHandler("audit_item");
      const result = await handler({
        sessionId,
        framework: "owasp",
        itemId: "INVALID_ITEM",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should record a pass result", async () => {
      const handler = getToolHandler("audit_item");
      const result = await handler({
        sessionId,
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good",
      });

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.status).toBe("pass");
    });

    it("should record a fail result", async () => {
      const handler = getToolHandler("audit_item");
      await handler({
        sessionId,
        framework: "owasp",
        itemId: "A02",
        status: "fail",
        notes: "Missing encryption",
      });
    });

    it("should update an existing result", async () => {
        const handler = getToolHandler("audit_item");
        const result = await handler({
            sessionId,
            framework: "owasp",
            itemId: "A01",
            status: "skip",
            notes: "Skipped for now",
        });
        const data = JSON.parse(result.content[0].text);
        expect(data.recorded.status).toBe("skip");
    });

    it("should generate a report in markdown format", async () => {
        const handler = getToolHandler("generate_report");
        const result = await handler({ sessionId, format: "markdown" });
        expect(result.content[0].type).toBe("text");
        expect(result.content[0].text).toContain("Security Audit Report");
        expect(result.content[0].text).toContain("Missing encryption");
    });

    it("should generate a report in JSON format", async () => {
        const handler = getToolHandler("generate_report");
        const result = await handler({ sessionId, format: "json" });
        const data = JSON.parse(result.content[0].text);
        expect(data.session).toBe(sessionId);
        expect(data.framework).toBe("OWASP Top 10");
        expect(data.summary.skipped).toBe(1);
        expect(data.summary.failed).toBe(1);
    });

    it("should generate a report in HTML format", async () => {
        const handler = getToolHandler("generate_report");
        const result = await handler({ sessionId, format: "html" });
        expect(result.content[0].text).toContain("<!DOCTYPE html>");
        expect(result.content[0].text).toContain("Security Audit Report");
    });

    it("should return an error for invalid session when generating report", async () => {
        const handler = getToolHandler("generate_report");
        const result = await handler({ sessionId: "invalid_session", format: "markdown" });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("not found");
    });
  });

  describe("get_risk_summary", () => {
    it("should return a risk summary for a framework", async () => {
      const handler = getToolHandler("get_risk_summary");
      const result = await handler({ framework: "owasp" });

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
    });
  });

  describe("search_controls", () => {
    it("should search across all frameworks", async () => {
      const handler = getToolHandler("search_controls");
      const result = await handler({ query: "encrypt", framework: "all" });

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.query).toBe("encrypt");
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });

    it("should search in a specific framework", async () => {
      const handler = getToolHandler("search_controls");
      const result = await handler({ query: "encrypt", framework: "owasp" });

      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(Object.keys(data.results)).toEqual(["OWASP Top 10"]);
    });

    it("should handle empty search results", async () => {
        const handler = getToolHandler("search_controls");
        const result = await handler({ query: "this-will-never-match-anything", framework: "all" });
        const data = JSON.parse(result.content[0].text);
        expect(data.totalMatches).toBe(0);
        expect(Object.keys(data.results).length).toBe(0);
    });
  });
});
