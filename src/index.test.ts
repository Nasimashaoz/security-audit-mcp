import { describe, it, expect, vi } from "vitest";
import { server, main } from "./index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// Mock the stdio transport since we can't connect real stdio in tests
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  const mockTransport = {
    start: vi.fn(),
    close: vi.fn(),
    send: vi.fn(),
  };
  return {
    StdioServerTransport: class {
      constructor() {
        return mockTransport;
      }
    },
  };
});

describe("security-audit-mcp server", () => {
  it("should have expected server configuration", () => {
    const serverAny = server as any;
    expect(serverAny.server._serverInfo.name).toBe("security-audit-mcp");
    expect(serverAny.server._serverInfo.version).toBe("1.0.0");
  });

  it("should start the server in main()", async () => {
    const connectSpy = vi.spyOn(server, "connect").mockResolvedValue(undefined);
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await main();

    expect(connectSpy).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("security-audit-mcp server running"));

    connectSpy.mockRestore();
    consoleSpy.mockRestore();
  });

  describe("tool: list_frameworks", () => {
    it("should return a list of all available frameworks", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["list_frameworks"].handler;

      const result = await handler({});

      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe("text");

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks).toBeDefined();
      expect(parsed.frameworks.length).toBeGreaterThan(0);

      const owasp = parsed.frameworks.find((f: any) => f.id === "owasp");
      expect(owasp).toBeDefined();
      expect(owasp.name).toBe("OWASP Top 10");
    });
  });

  describe("tool: audit_item", () => {
    it("should successfully record a pass result", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["audit_item"].handler;

      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });

      expect(result.content).toHaveLength(1);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.itemId).toBe("A01");
      expect(parsed.recorded.status).toBe("pass");
      expect(parsed.recorded.notes).toBe("Looks good");
    });

    it("should return an error if item is not found", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["audit_item"].handler;

      const result = await handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "INVALID-ITEM",
        status: "pass"
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("tool: generate_report", () => {
    it("should generate a report for an existing session", async () => {
      const serverAny = server as any;
      // Pre-seed a session by recording an item
      await serverAny._registeredTools["audit_item"].handler({
        sessionId: "report-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Missing controls"
      });

      const handler = serverAny._registeredTools["generate_report"].handler;
      const result = await handler({
        sessionId: "report-session-1",
        format: "json"
      });

      expect(result.content).toHaveLength(1);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.session).toBe("report-session-1");
      expect(parsed.framework).toBe("OWASP Top 10");
      expect(parsed.summary.failed).toBe(1);
      expect(parsed.allResults[0].itemId).toBe("A01");
    });

    it("should return an error for a non-existent session", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["generate_report"].handler;

      const result = await handler({
        sessionId: "non-existent-session",
        format: "json"
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("tool: get_framework", () => {
    it("should return the full checklist for a valid framework", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["get_framework"].handler;

      const result = await handler({ framework: "owasp" });

      expect(result.content).toHaveLength(1);
      expect(result.content[0].type).toBe("text");

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe("OWASP Top 10");
      expect(parsed.items).toBeDefined();
      expect(parsed.items.length).toBeGreaterThan(0);
    });

    it("should return an error for an invalid framework", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["get_framework"].handler;

      const result = await handler({ framework: "invalid_fw" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("tool: get_risk_summary", () => {
    it("should return a risk summary for a given framework", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["get_risk_summary"].handler;

      const result = await handler({ framework: "owasp" });

      expect(result.content).toHaveLength(1);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.framework).toBe("OWASP Top 10");
      expect(parsed.riskBreakdown).toBeDefined();
      expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
      expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(parsed.riskBreakdown.CRITICAL[0]).toContain("A01:");
    });
  });

  describe("tool: search_controls", () => {
    it("should return search results across all frameworks by default", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["search_controls"].handler;

      const result = await handler({ query: "encrypt", framework: "all" });

      expect(result.content).toHaveLength(1);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.query).toBe("encrypt");
      expect(parsed.totalMatches).toBeGreaterThan(0);

      // Check that it searched OWASP since Cryptographic Failures contains "encrypt"
      expect(parsed.results["OWASP Top 10"]).toBeDefined();
    });

    it("should limit search results to a specific framework", async () => {
      const serverAny = server as any;
      const handler = serverAny._registeredTools["search_controls"].handler;

      const result = await handler({ query: "encrypt", framework: "owasp" });

      expect(result.content).toHaveLength(1);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.query).toBe("encrypt");
      expect(parsed.results["OWASP Top 10"]).toBeDefined();
      // other frameworks should be undefined
      expect(parsed.results["NIST SP 800-53"]).toBeUndefined();
    });
  });
});
