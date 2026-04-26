import { describe, it, expect, vi } from "vitest";
import { server } from "./index.js";

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

describe("security-audit-mcp tools", () => {
  const tools = (server as any)._registeredTools;

  it("should list frameworks via list_frameworks", async () => {
    const listFrameworksTool = tools.list_frameworks as any;
    expect(listFrameworksTool).toBeDefined();

    const response = await listFrameworksTool.handler({});
    expect(response.content).toHaveLength(1);
    expect(response.content[0].type).toBe("text");

    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.frameworks).toBeInstanceOf(Array);
    expect(parsed.frameworks.some((fw: any) => fw.id === "owasp")).toBe(true);
    expect(parsed.frameworks.some((fw: any) => fw.id === "pcidss")).toBe(true);
  });

  it("should return the full checklist for a specific framework via get_framework", async () => {
    const getFrameworkTool = tools.get_framework as any;
    expect(getFrameworkTool).toBeDefined();

    const response = await getFrameworkTool.handler({ framework: "owasp" });
    expect(response.content).toHaveLength(1);

    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.name).toBe("OWASP Top 10");
    expect(parsed.items).toBeInstanceOf(Array);
  });

  it("should return an error for a non-existent framework via get_framework", async () => {
    const getFrameworkTool = tools.get_framework as any;

    // Note: Zod validation handles this at the MCP protocol level,
    // but we can test the internal handler if we bypass Zod validation by calling handler directly
    // However, the handler still checks `if (!fw) { return error }`
    const response = await getFrameworkTool.handler({ framework: "non-existent" });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("should record an audit item result and generate report", async () => {
    const auditItemTool = tools.audit_item as any;
    const sessionId = "test-session-1";

    const response = await auditItemTool.handler({
      sessionId,
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "Test notes"
    });

    expect(response.content).toBeDefined();
    const parsedAudit = JSON.parse(response.content[0].text);
    expect(parsedAudit.recorded.status).toBe("pass");
    expect(parsedAudit.recorded.notes).toBe("Test notes");

    const generateReportTool = tools.generate_report as any;

    // Test JSON format
    const jsonReport = await generateReportTool.handler({
      sessionId,
      format: "json"
    });
    const parsedJsonReport = JSON.parse(jsonReport.content[0].text);
    expect(parsedJsonReport.summary.passed).toBe(1);
    expect(parsedJsonReport.summary.failed).toBe(0);

    // Test Markdown format
    const mdReport = await generateReportTool.handler({
      sessionId,
      format: "markdown"
    });
    expect(mdReport.content[0].text).toContain("🔒 Security Audit Report");
    expect(mdReport.content[0].text).toContain("Test notes");
  });

  it("should get risk summary", async () => {
    const riskSummaryTool = tools.get_risk_summary as any;

    const response = await riskSummaryTool.handler({ framework: "iso27001" });
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.framework).toBe("ISO 27001");
    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
    expect(parsed.riskBreakdown.HIGH).toBeDefined();
  });

  it("should search controls", async () => {
    const searchControlsTool = tools.search_controls as any;

    const response = await searchControlsTool.handler({ query: "authentication", framework: "all" });
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.query).toBe("authentication");
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(parsed.results).length).toBeGreaterThan(0);
  });
});
