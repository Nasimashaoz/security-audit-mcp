import { describe, it, expect, beforeEach } from "vitest";
import { server, sessions } from "../src/index.js";
import { FRAMEWORKS } from "../src/frameworks.js";

describe("Security Audit MCP Server", () => {
  beforeEach(() => {
    sessions.clear();
  });

  const getTool = (name: string) => {
    const tools = (server as any)._registeredTools;
    if (!tools) {
      throw new Error("Tools not found on server instance");
    }
    return tools[name];
  };

  it("list_frameworks tool should return available frameworks", async () => {
    const tool = getTool("list_frameworks");
    expect(tool).toBeDefined();

    const response = await tool.handler({});
    expect(response.content[0].type).toBe("text");

    const data = JSON.parse(response.content[0].text);
    expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    expect(data.frameworks.some((f: any) => f.id === "pcidss")).toBe(true);
  });

  it("get_framework tool should return a specific framework", async () => {
    const tool = getTool("get_framework");
    const response = await tool.handler({ framework: "owasp" });
    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
  });

  it("get_framework tool should return error for unknown framework", async () => {
    const tool = getTool("get_framework");
    // Should fail schema validation realistically, but let's test handler
    const response = await tool.handler({ framework: "unknown_framework" });
    expect(response.isError).toBe(true);
  });

  it("audit_item tool should record a result", async () => {
    const tool = getTool("audit_item");
    const response = await tool.handler({
      sessionId: "test-session-1",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "Looks good"
    });

    const data = JSON.parse(response.content[0].text);
    expect(data.recorded.itemId).toBe("A01");
    expect(data.recorded.status).toBe("pass");
    expect(sessions.has("test-session-1")).toBe(true);
  });

  it("audit_item tool should return error for unknown item", async () => {
    const tool = getTool("audit_item");
    const response = await tool.handler({
      sessionId: "test-session-2",
      framework: "owasp",
      itemId: "UNKNOWN_ITEM",
      status: "pass",
    });

    expect(response.isError).toBe(true);
  });

  it("generate_report tool should generate a JSON report", async () => {
    const auditTool = getTool("audit_item");
    await auditTool.handler({
      sessionId: "report-session-1",
      framework: "nist",
      itemId: "AC-1",
      status: "fail",
      notes: "Missing policy"
    });

    const reportTool = getTool("generate_report");
    const response = await reportTool.handler({
      sessionId: "report-session-1",
      format: "json"
    });

    const data = JSON.parse(response.content[0].text);
    expect(data.session).toBe("report-session-1");
    expect(data.summary.failed).toBe(1);
    expect(data.score).toBe("0%");
  });

  it("generate_report tool should return markdown by default", async () => {
    const auditTool = getTool("audit_item");
    await auditTool.handler({
      sessionId: "report-session-2",
      framework: "iso27001",
      itemId: "A.5.1",
      status: "pass"
    });

    const reportTool = getTool("generate_report");
    const response = await reportTool.handler({
      sessionId: "report-session-2",
      format: "markdown"
    });

    expect(response.content[0].text).toContain("# 🔒 Security Audit Report");
    expect(response.content[0].text).toContain("ISO 27001");
  });

  it("generate_report tool should return html when requested", async () => {
    const auditTool = getTool("audit_item");
    await auditTool.handler({
      sessionId: "report-session-3",
      framework: "soc2",
      itemId: "CC1",
      status: "fail"
    });

    const reportTool = getTool("generate_report");
    const response = await reportTool.handler({
      sessionId: "report-session-3",
      format: "html"
    });

    expect(response.content[0].text).toContain("<!DOCTYPE html>");
    expect(response.content[0].text).toContain("SOC 2 Type II");
  });

  it("generate_report tool should return error for unknown session", async () => {
    const reportTool = getTool("generate_report");
    const response = await reportTool.handler({
      sessionId: "unknown-session",
      format: "markdown"
    });

    expect(response.isError).toBe(true);
  });

  it("get_risk_summary tool should summarize risks", async () => {
    const tool = getTool("get_risk_summary");
    const response = await tool.handler({ framework: "pcidss" });
    const data = JSON.parse(response.content[0].text);

    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
  });

  it("search_controls tool should search across all frameworks", async () => {
    const tool = getTool("search_controls");
    const response = await tool.handler({
      query: "encryption",
      framework: "all"
    });

    const data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
  });

  it("search_controls tool should search within a specific framework", async () => {
    const tool = getTool("search_controls");
    const response = await tool.handler({
      query: "access",
      framework: "iso27001"
    });

    const data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(data.results)).toEqual(["ISO 27001"]);
  });
});
