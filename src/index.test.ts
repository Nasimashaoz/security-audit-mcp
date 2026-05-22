import { describe, it, expect, beforeEach, vi } from "vitest";
import { server, sessions } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

// Utility to directly invoke the tools using the MCP Server's internal assertToolCall method
const getToolHandler = (name: string) => {
  return async (args: any) => {
    // Instead of using private _registeredTools, we can use the server's registered tools map directly if we cast it.
    // However, the best way to test tools without a transport is to use the request handlers map if populated,
    // or simulate it via the SDK's internal machinery if necessary.
    // Wait, the MCP SDK exposes a way to call tools via the Server instance.

    // As memory said: "In vitest, MCP tools can be tested directly without going through the full protocol request lifecycle by accessing the internal tools object via `(server as any)._registeredTools` and invoking `tools[name]?.handler(args)`."
    // Let's use the exact method from memory, since we saw it populated earlier.
    const tools = (server as any)._registeredTools || (server as any)._tools || (server.server as any)._registeredTools || (server as any).tools;
    let tool = null;
    if (tools) {
      tool = tools[name] || (tools instanceof Map ? tools.get(name) : null);
    }

    // If not found in the obvious places, we can just instantiate the handler from the tools array if it's there
    if (!tool && Array.isArray(tools)) {
      tool = tools.find((t: any) => t.name === name);
    }

    if (!tool && server.server._requestHandlers) {
       // fallback if we need to call it via request handler
       const result = await server.server._requestHandlers["tools/call"]({
         method: "tools/call",
         params: { name, arguments: args }
       });
       return result;
    }

    if (!tool) {
       // Deep fallback for test: we just lookup from the list of tools since we know they're registered.
       // The server object has an array of tools or a map. Let's dump to see.
       throw new Error(`Tool ${name} not found`);
    }

    // It expects { [key]: value } as argument instead of `{ params: ... }` based on how McpServer.tool wraps it
    return await tool.handler(args);
  };
};

describe("security-audit-mcp server tools", () => {
  beforeEach(() => {
    sessions.clear();
    vi.restoreAllMocks();
  });

  it("should list all frameworks", async () => {
    const handler = getToolHandler("list_frameworks");
    const result = await handler({});

    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);

    expect(data.frameworks).toBeInstanceOf(Array);
    expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    expect(data.frameworks.map((fw: any) => fw.id)).toEqual(
      expect.arrayContaining(["owasp", "nist", "iso27001", "pcidss", "soc2", "hipaa", "cisv8", "gdpr"])
    );
  });

  it("should get a framework checklist", async () => {
    const handler = getToolHandler("get_framework");
    const result = await handler({ framework: "owasp" });

    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
    expect(data.items.length).toBeGreaterThan(0);
  });

  it("should audit an item and store it in session", async () => {
    const handler = getToolHandler("audit_item");

    const sessionId = "test-session";
    const result = await handler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Missing role checks"
    });

    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.recorded.itemId).toBe("A01");
    expect(data.recorded.status).toBe("fail");

    const session = sessions.get(sessionId);
    expect(session).toBeDefined();
    expect(session?.framework).toBe("owasp");
    expect(session?.results).toHaveLength(1);
    expect(session?.results[0].notes).toBe("Missing role checks");
  });

  it("should generate a report in different formats", async () => {
    const auditHandler = getToolHandler("audit_item");
    const reportHandler = getToolHandler("generate_report");

    const sessionId = "report-test";
    await auditHandler({ sessionId, framework: "nist", itemId: "AC-1", status: "pass" });
    await auditHandler({ sessionId, framework: "nist", itemId: "AC-2", status: "fail", notes: "bad" });

    const jsonResult = await reportHandler({ sessionId, format: "json" });
    const jsonData = JSON.parse(jsonResult.content[0].text);
    expect(jsonData.score).toBe("50%");
    expect(jsonData.summary.passed).toBe(1);
    expect(jsonData.summary.failed).toBe(1);

    const mdResult = await reportHandler({ sessionId, format: "markdown" });
    expect(mdResult.content[0].text).toContain("# 🔒 Security Audit Report");
    expect(mdResult.content[0].text).toContain("50%");

    const htmlResult = await reportHandler({ sessionId, format: "html" });
    expect(htmlResult.content[0].text).toContain("<!DOCTYPE html>");
    expect(htmlResult.content[0].text).toContain("50%");
  });

  it("should get risk summary", async () => {
    const handler = getToolHandler("get_risk_summary");
    const result = await handler({ framework: "iso27001" });

    const data = JSON.parse(result.content[0].text);
    expect(data.framework).toBe("ISO 27001");
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("should search controls", async () => {
    const handler = getToolHandler("search_controls");

    const resultAll = await handler({ query: "authentication", framework: "all" });
    const dataAll = JSON.parse(resultAll.content[0].text);
    expect(dataAll.totalMatches).toBeGreaterThan(0);

    const resultOwasp = await handler({ query: "injection", framework: "owasp" });
    const dataOwasp = JSON.parse(resultOwasp.content[0].text);
    expect(dataOwasp.results["OWASP Top 10"]).toBeDefined();
  });

  it("should lookup CVE", async () => {
    const handler = getToolHandler("cve_lookup");

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        cveMetadata: { cveId: "CVE-2021-44228", state: "PUBLISHED" }
      })
    });

    const result = await handler({ cveId: "CVE-2021-44228" });
    const data = JSON.parse(result.content[0].text);
    expect(data.cveId).toBe("CVE-2021-44228");
    expect(data.state).toBe("PUBLISHED");
  });

  it("should handle CVE lookup errors", async () => {
    const handler = getToolHandler("cve_lookup");

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found"
    });

    const result = await handler({ cveId: "CVE-UNKNOWN" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("CVE 'CVE-UNKNOWN' not found.");
  });
});
