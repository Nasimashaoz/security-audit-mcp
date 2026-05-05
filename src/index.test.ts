import { describe, it, expect, vi } from "vitest";
import { server } from "./index.js";

// Mock stdio server transport to prevent any actual IO
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      connect() {}
      close() {}
    },
  };
});

describe("security-audit-mcp tools", () => {
  const tools = (server as any)._registeredTools;

  it("should have all registered tools", () => {
    expect(tools).toHaveProperty("list_frameworks");
    expect(tools).toHaveProperty("get_framework");
    expect(tools).toHaveProperty("audit_item");
    expect(tools).toHaveProperty("generate_report");
    expect(tools).toHaveProperty("get_risk_summary");
    expect(tools).toHaveProperty("search_controls");
  });

  describe("list_frameworks", () => {
    it("should list all frameworks including newly added ones", async () => {
      const result = await tools["list_frameworks"].handler({});
      expect(result.content[0].text).toContain("owasp");
      expect(result.content[0].text).toContain("nist");
      expect(result.content[0].text).toContain("iso27001");
      expect(result.content[0].text).toContain("pcidss");
      expect(result.content[0].text).toContain("soc2");
      expect(result.content[0].text).toContain("hipaa");
      expect(result.content[0].text).toContain("cisv8");
      expect(result.content[0].text).toContain("gdpr");
    });
  });

  describe("get_framework", () => {
    it("should return the specified framework", async () => {
      const result = await tools["get_framework"].handler({ framework: "owasp" });
      expect(result.content[0].text).toContain("OWASP Top 10");
    });

    it("should return an error if framework is not found", async () => {
      const result = await tools["get_framework"].handler({ framework: "nonexistent" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("audit_item", () => {
    it("should record a pass/fail/skip result for an audit control item", async () => {
      const result = await tools["audit_item"].handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good",
      });
      expect(result.content[0].text).toContain("A01");
      expect(result.content[0].text).toContain("pass");
      expect(result.content[0].text).toContain("Looks good");

      const updateResult = await tools["audit_item"].handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Failed now",
      });
      expect(updateResult.content[0].text).toContain("fail");
    });

    it("should return an error if item is not found", async () => {
      const result = await tools["audit_item"].handler({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A99",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("generate_report", () => {
    it("should generate a report in markdown format", async () => {
      await tools["audit_item"].handler({
        sessionId: "test-session-2",
        framework: "nist",
        itemId: "AC-1",
        status: "pass",
      });

      const result = await tools["generate_report"].handler({
        sessionId: "test-session-2",
        format: "markdown",
      });
      expect(result.content[0].text).toContain("## NIST SP 800-53");
      expect(result.content[0].text).toContain("AC-1");
    });

    it("should generate a report in HTML format", async () => {
      await tools["audit_item"].handler({
        sessionId: "test-session-3",
        framework: "pcidss",
        itemId: "Req-1",
        status: "fail",
        notes: "Missing firewall rules",
      });

      const result = await tools["generate_report"].handler({
        sessionId: "test-session-3",
        format: "html",
      });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("PCI-DSS");
      expect(result.content[0].text).toContain("Req-1");
      expect(result.content[0].text).toContain("Missing firewall rules");
    });

    it("should generate a report in JSON format", async () => {
      await tools["audit_item"].handler({
        sessionId: "test-session-4",
        framework: "soc2",
        itemId: "CC1",
        status: "skip",
      });

      const result = await tools["generate_report"].handler({
        sessionId: "test-session-4",
        format: "json",
      });
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe("test-session-4");
      expect(data.framework).toBe("SOC 2");
      expect(data.summary.skipped).toBe(1);
    });

    it("should include critical findings correctly", async () => {
      await tools["audit_item"].handler({
        sessionId: "test-session-5",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
      });

      const result = await tools["generate_report"].handler({
        sessionId: "test-session-5",
        format: "markdown",
      });
      expect(result.content[0].text).toContain("## 🚨 Critical Findings");
      expect(result.content[0].text).toContain("A01");
    });

    it("should return an error if session is not found", async () => {
      const result = await tools["generate_report"].handler({
        sessionId: "nonexistent-session",
        format: "markdown",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("get_risk_summary", () => {
    it("should return risk summary for a given framework", async () => {
      const result = await tools["get_risk_summary"].handler({
        framework: "iso27001",
      });
      expect(result.content[0].text).toContain("CRITICAL");
      expect(result.content[0].text).toContain("HIGH");
      expect(result.content[0].text).toContain("A.5.15");
    });
  });

  describe("search_controls", () => {
    it("should search controls across all frameworks", async () => {
      const result = await tools["search_controls"].handler({
        query: "encrypt",
        framework: "all",
      });
      expect(result.content[0].text).toContain("totalMatches");
      expect(result.content[0].text).toContain("Cryptographic Failures"); // OWASP
    });

    it("should search controls within a specific framework", async () => {
      const result = await tools["search_controls"].handler({
        query: "encrypt",
        framework: "nist",
      });
      const data = JSON.parse(result.content[0].text);
      expect(data.results["NIST SP 800-53"]).toBeDefined();
      expect(data.results["OWASP Top 10"]).toBeUndefined();
    });

    it("should handle empty search results", async () => {
      const result = await tools["search_controls"].handler({
        query: "nonexistentstring123",
        framework: "all",
      });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBe(0);
    });
  });
});
