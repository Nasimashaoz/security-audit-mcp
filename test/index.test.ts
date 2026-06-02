import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server, sessions } from "../src/index.js";
import { FRAMEWORKS } from "../src/frameworks.js";

// Mock the StdioServerTransport as it cannot be tested in typical node environment
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    }
  };
});

describe("security-audit-mcp server tools", () => {
  let toolsMap: any;

  beforeEach(() => {
    // Access internal registered tools for testing handlers directly
    const rawTools = (server as any)._registeredTools;
    toolsMap = rawTools instanceof Map ? rawTools : new Map(Object.entries(rawTools));
    // In newer MCP SDK, _registeredTools may be an object
    const tools = toolsMap instanceof Map ? toolsMap : new Map(Object.entries(toolsMap));
    toolsMap = tools;
    sessions.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should have registered all expected tools", () => {
    expect(toolsMap.has("list_frameworks")).toBe(true);
    expect(toolsMap.has("get_framework")).toBe(true);
    expect(toolsMap.has("audit_item")).toBe(true);
    expect(toolsMap.has("generate_report")).toBe(true);
    expect(toolsMap.has("get_risk_summary")).toBe(true);
    expect(toolsMap.has("search_controls")).toBe(true);
    expect(toolsMap.has("cve_lookup")).toBe(true);
  });

  describe("list_frameworks", () => {
    it("should list all available frameworks", async () => {
      const handler = toolsMap.get("list_frameworks").handler;
      const result = await handler({});

      const content = JSON.parse(result.content[0].text);
      expect(content.frameworks).toBeDefined();
      expect(content.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(content.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
      expect(content.frameworks.some((f: any) => f.id === "gdpr")).toBe(true);
    });
  });

  describe("get_framework", () => {
    it("should return framework details for a valid framework", async () => {
      const handler = toolsMap.get("get_framework").handler;
      const result = await handler({ framework: "owasp" });

      const content = JSON.parse(result.content[0].text);
      expect(content.name).toBe("OWASP Top 10");
      expect(content.items).toBeDefined();
      expect(result.isError).toBeUndefined();
    });

    it("should return an error for an invalid framework", async () => {
      // Bypassing TS compiler checks as we test for runtime error handling
      const handler = toolsMap.get("get_framework").handler;
      const result = await handler({ framework: "nonexistent" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item", () => {
    it("should record an audit result successfully", async () => {
      const handler = toolsMap.get("audit_item").handler;
      const sessionId = "test-session";

      const result = await handler({
        sessionId,
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Test notes"
      });

      expect(result.isError).toBeUndefined();

      const session = sessions.get(sessionId);
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].itemId).toBe("A01");
      expect(session?.results[0].status).toBe("fail");
    });
  });

  describe("search_controls", () => {
    it("should search for controls across all frameworks", async () => {
      const handler = toolsMap.get("search_controls").handler;

      const result = await handler({
        query: "encryption",
        framework: "all"
      });

      const content = JSON.parse(result.content[0].text);
      expect(content.totalMatches).toBeGreaterThan(0);
      expect(content.results).toBeDefined();
    });
  });

  describe("cve_lookup", () => {
    it("should fetch CVE details successfully", async () => {
      const mockResponse = {
        cveMetadata: {
          cveId: "CVE-2021-44228"
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      });

      const handler = toolsMap.get("cve_lookup").handler;
      const result = await handler({ cveId: "CVE-2021-44228" });

      const content = JSON.parse(result.content[0].text);
      expect(content.cveMetadata.cveId).toBe("CVE-2021-44228");
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle CVE not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      });

      const handler = toolsMap.get("cve_lookup").handler;
      const result = await handler({ cveId: "CVE-2021-0000" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should validate CVE format", async () => {
      const handler = toolsMap.get("cve_lookup").handler;
      const result = await handler({ cveId: "invalid-format" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Invalid CVE ID format");
    });
  });
});
