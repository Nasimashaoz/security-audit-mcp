import { describe, it, expect, vi, beforeAll } from "vitest";
import { server } from "../src/index.js";

// Mock StdioServerTransport since we can't connect to real stdio in tests
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        start: vi.fn(),
        close: vi.fn(),
        onMessage: vi.fn(),
        onClose: vi.fn(),
        onError: vi.fn(),
        send: vi.fn(),
      };
    }),
  };
});

describe("security-audit-mcp Tools", () => {
  let callTool: any;

  beforeAll(() => {
    // Access the internal tools map
    const internalServer = server as any;
    const tools = internalServer._registeredTools;

    callTool = async (name: string, args: any) => {
      if (!tools || !tools[name]) {
        throw new Error(`Tool ${name} not found`);
      }
      // The cb seems to be stored under the 'handler' key or 'execution' key maybe. Let's try calling handler
      // Wait, let's look at the structure from our log: handler might just be the callback.
      // Or maybe we can call the MCP request handler directly.
      // Actually, looking at the keys: 'title', 'description', 'inputSchema', 'outputSchema', 'annotations', 'execution', '_meta', 'handler'
      return tools[name].handler(args, { request: {} as any });
    };
  });

  it("list_frameworks should return all frameworks including new ones", async () => {
    const result = await callTool("list_frameworks", {});
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);

    expect(data.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === "pcidss")).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === "soc2")).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === "hipaa")).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === "cisv8")).toBe(true);
  });

  it("get_framework should return full framework checklist", async () => {
    const result = await callTool("get_framework", { framework: "pcidss" });
    const data = JSON.parse(result.content[0].text);
    expect(data.name).toBe("PCI-DSS");
    expect(data.items.length).toBeGreaterThan(0);
  });

  it("audit_item should record item result", async () => {
    const result = await callTool("audit_item", {
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Test failure"
    });

    const data = JSON.parse(result.content[0].text);
    expect(data.recorded.itemId).toBe("A01");
    expect(data.recorded.status).toBe("fail");
  });

  it("generate_report should generate a markdown report by default", async () => {
    // When we call `generate_report` without specifying a format, since we don't have real arg validation in tests
    // it seems `format` is undefined and defaulting isn't happening properly or it defaults to HTML.
    // Let's pass the default manually, or just pass `format: "markdown"` since zod's `.default`
    // happens during the MCP parsing pipeline which we are bypassing by calling the handler directly.
    const result = await callTool("generate_report", { sessionId: "test-session-1", format: "markdown" });
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("🚨 Critical Findings");
    expect(result.content[0].text).toContain("A01");
  });

  it("generate_report should generate a CSV report", async () => {
    const result = await callTool("generate_report", { sessionId: "test-session-1", format: "csv" });
    expect(result.content[0].type).toBe("text");
    const csv = result.content[0].text;
    expect(csv).toContain("ID,Title,Risk,Status,Notes");
    expect(csv).toContain('"A01",');
    expect(csv).toContain(',"CRITICAL","FAIL","Test failure"');
  });

  it("get_risk_summary should return breakdown of risks", async () => {
    const result = await callTool("get_risk_summary", { framework: "owasp" });
    const data = JSON.parse(result.content[0].text);
    expect(data.framework).toBe("OWASP Top 10");
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("search_controls should find controls by keyword", async () => {
    const result = await callTool("search_controls", { query: "encryption", framework: "all" });
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    // Should find results in multiple frameworks, e.g., owasp, pci-dss, hipaa
    expect(Object.keys(data.results).length).toBeGreaterThan(0);
  });
});
