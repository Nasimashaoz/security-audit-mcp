import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "../src/index.js";
import { FRAMEWORKS } from "../src/frameworks.js";

// Mock StdioServerTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        start: vi.fn(),
        close: vi.fn(),
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn(),
        send: vi.fn(),
      };
    }),
  };
});

describe("MCP Tools", () => {
  let tools: any;

  beforeEach(() => {
    tools = (server as any)._registeredTools;
  });

  const callTool = async (name: string, args: any) => {
    const handler = tools[name];
    if (!handler) {
      throw new Error(`Tool ${name} not found`);
    }
    // According to SDK implementation, the handler is usually passed the args directly or via a specific signature.
    // The memory states: `tools[name]?.handler(args)`
    // Let's check what `tools[name]` is - if it's an object with a `handler` property or a function itself.
    // Actually, `_registeredTools` maps name to `{ tool, handler }` or something similar, or just the tool directly if it's not the raw server.
    // Let's assume the memory instruction `tools[name]?.handler(args)` is the exact way.
    if (typeof handler === "function") {
        return handler(args);
    } else if (handler && handler.handler) {
        return handler.handler(args, { request: {} }); // Providing a dummy context just in case
    }
  };

  it("should have all registered tools", () => {
    expect(tools).toBeDefined();
    expect(Object.keys(tools)).toContain("list_frameworks");
    expect(Object.keys(tools)).toContain("get_framework");
    expect(Object.keys(tools)).toContain("audit_item");
    expect(Object.keys(tools)).toContain("generate_report");
    expect(Object.keys(tools)).toContain("get_risk_summary");
    expect(Object.keys(tools)).toContain("search_controls");
  });

  it("list_frameworks should return all frameworks", async () => {
    const response = await callTool("list_frameworks", {});
    expect(response.content).toBeDefined();
    expect(response.content[0].type).toBe("text");
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.frameworks).toBeDefined();
    expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
  });

  it("get_framework should return a specific framework", async () => {
    const response = await callTool("get_framework", { framework: "owasp" });
    expect(response.content).toBeDefined();
    expect(response.content[0].type).toBe("text");
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.name).toBe("OWASP Top 10");
    expect(parsed.items.length).toBeGreaterThan(0);
  });

  it("get_framework should return error for invalid framework", async () => {
    const response = await callTool("get_framework", { framework: "invalid" });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("audit_item should record a result and update progress", async () => {
    const sessionId = "test-session-1";
    const response = await callTool("audit_item", {
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Failed access control test",
    });

    expect(response.content[0].text).toContain("Failed access control test");
    expect(response.content[0].text).toContain("fail");
  });

  it("audit_item should return error for invalid item", async () => {
    const response = await callTool("audit_item", {
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "INVALID-ITEM",
      status: "pass",
    });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("generate_report should generate markdown report correctly", async () => {
    const sessionId = "test-session-2";
    await callTool("audit_item", {
      sessionId,
      framework: "nist",
      itemId: "AC-1",
      status: "pass",
      notes: "Looks good",
    });

    const response = await callTool("generate_report", {
      sessionId,
      format: "markdown",
    });

    expect(response.content[0].text).toContain("NIST SP 800-53");
    expect(response.content[0].text).toContain("AC-1");
    expect(response.content[0].text).toContain("Looks good");
  });

  it("generate_report should generate JSON report correctly", async () => {
    const sessionId = "test-session-3";
    await callTool("audit_item", {
      sessionId,
      framework: "iso27001",
      itemId: "A.5.1",
      status: "fail",
    });

    const response = await callTool("generate_report", {
      sessionId,
      format: "json",
    });

    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.session).toBe(sessionId);
    expect(parsed.framework).toBe("ISO 27001");
    expect(parsed.summary.failed).toBe(1);
  });

  it("generate_report should generate HTML report correctly", async () => {
    const sessionId = "test-session-4";
    await callTool("audit_item", {
      sessionId,
      framework: "pcidss",
      itemId: "Req-1",
      status: "skip",
    });

    const response = await callTool("generate_report", {
      sessionId,
      format: "html",
    });

    expect(response.content[0].text).toContain("<!DOCTYPE html>");
    expect(response.content[0].text).toContain("Req-1");
    expect(response.content[0].text).toContain("SKIP");
  });

  it("generate_report should return error for non-existent session", async () => {
    const response = await callTool("generate_report", {
      sessionId: "does-not-exist",
      format: "json",
    });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("get_risk_summary should group items by risk correctly", async () => {
    const response = await callTool("get_risk_summary", { framework: "cisv8" });
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.framework).toBe("CIS Controls v8");
    expect(parsed.riskBreakdown).toBeDefined();
    expect(Array.isArray(parsed.riskBreakdown.CRITICAL)).toBe(true);
    expect(Array.isArray(parsed.riskBreakdown.HIGH)).toBe(true);
    expect(Array.isArray(parsed.riskBreakdown.MEDIUM)).toBe(true);
    expect(Array.isArray(parsed.riskBreakdown.LOW)).toBe(true);
  });

  it("search_controls should find controls by keyword across all frameworks", async () => {
    const response = await callTool("search_controls", {
      query: "authentication",
      framework: "all",
    });
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.query).toBe("authentication");
    expect(parsed.totalMatches).toBeGreaterThan(0);
    // Should match in multiple frameworks (e.g. owasp, nist, iso27001)
    expect(Object.keys(parsed.results).length).toBeGreaterThan(0);
  });

  it("search_controls should find controls by keyword in a specific framework", async () => {
    const response = await callTool("search_controls", {
      query: "crypt",
      framework: "owasp",
    });
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.query).toBe("crypt");
    expect(parsed.results["OWASP Top 10"]).toBeDefined();
    // It should not include results from other frameworks
    if (parsed.totalMatches > 0) {
       expect(Object.keys(parsed.results).length).toBe(1);
    }
  });

});
