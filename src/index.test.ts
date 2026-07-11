import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  listFrameworksHandler,
  getFrameworkHandler,
  auditItemHandler,
  generateReportHandler,
  getRiskSummaryHandler,
  searchControlsHandler,
  cveLookupHandler,
  sessions,
  main
} from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

describe("Tool Handlers", () => {
  beforeEach(() => {
    sessions.clear();
  });

  describe("listFrameworksHandler", () => {
    it("should return a list of all available frameworks", async () => {
      const response = await listFrameworksHandler();
      expect(response.content.length).toBe(1);
      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(data.frameworks[0].id).toBeDefined();
      expect(data.frameworks[0].name).toBeDefined();
    });
  });

  describe("getFrameworkHandler", () => {
    it("should return the framework details for a valid framework", async () => {
      const response = await getFrameworkHandler({ framework: "owasp" });
      expect(response.isError).toBeUndefined();
      expect(response.content.length).toBe(1);
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items.length).toBeGreaterThan(0);
    });

    it("should return an error for an invalid framework", async () => {
      const response = await getFrameworkHandler({ framework: "invalid" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("auditItemHandler", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("should record a new audit result", async () => {
      const response = await auditItemHandler({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });

      expect(response.isError).toBeUndefined();

      const session = sessions.get("session-1");
      expect(session).toBeDefined();
      expect(session?.framework).toBe("owasp");
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].itemId).toBe("A01");
      expect(session?.results[0].status).toBe("pass");
      expect(session?.results[0].notes).toBe("Looks good");
    });

    it("should update an existing audit result", async () => {
      await auditItemHandler({ sessionId: "session-1", framework: "owasp", itemId: "A01", status: "fail" });
      await auditItemHandler({ sessionId: "session-1", framework: "owasp", itemId: "A01", status: "pass", notes: "Fixed" });

      const session = sessions.get("session-1");
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].status).toBe("pass");
      expect(session?.results[0].notes).toBe("Fixed");
    });

    it("should return an error for invalid item id", async () => {
      const response = await auditItemHandler({ sessionId: "session-1", framework: "owasp", itemId: "INVALID", status: "pass" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("generateReportHandler", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));

      // Setup a mock session
      sessions.set("session-1", {
        id: "session-1",
        framework: "owasp",
        startedAt: new Date().toISOString(),
        results: [
          { itemId: "A01", title: "Broken Access Control", risk: "CRITICAL", status: "pass", notes: "" },
          { itemId: "A02", title: "Cryptographic Failures", risk: "CRITICAL", status: "fail", notes: "Needs encryption" }
        ]
      });
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("should generate a JSON report", async () => {
      const response = await generateReportHandler({ sessionId: "session-1", format: "json" });
      expect(response.isError).toBeUndefined();

      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe("session-1");
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.score).toBe("50%");
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.criticalFindings.length).toBe(1);
    });

    it("should generate a Markdown report", async () => {
      const response = await generateReportHandler({ sessionId: "session-1", format: "markdown" });
      expect(response.isError).toBeUndefined();

      const markdown = response.content[0].text;
      expect(markdown).toContain("# 🔒 Security Audit Report");
      expect(markdown).toContain("**Score:** 50%");
      expect(markdown).toContain("## 🚨 Critical Findings");
      expect(markdown).toContain("- **A02** Cryptographic Failures: Needs encryption");
    });

    it("should generate an HTML report", async () => {
      const response = await generateReportHandler({ sessionId: "session-1", format: "html" });
      expect(response.isError).toBeUndefined();

      const html = response.content[0].text;
      expect(html).toContain("<!DOCTYPE html>");
      expect(html).toContain("<h1>🔒 Security Audit Report</h1>");
      expect(html).toContain("<div class=\"score\">50%</div>");
    });

    it("should return an error if session is not found", async () => {
      const response = await generateReportHandler({ sessionId: "non-existent", format: "json" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("getRiskSummaryHandler", () => {
    it("should return a risk summary for a framework", async () => {
      const response = await getRiskSummaryHandler({ framework: "owasp" });
      expect(response.isError).toBeUndefined();

      const data = JSON.parse(response.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown).toBeDefined();
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(data.riskBreakdown.CRITICAL[0]).toContain("A01:");
    });
  });

  describe("searchControlsHandler", () => {
    it("should search across all frameworks", async () => {
      const response = await searchControlsHandler({ query: "authentication", framework: "all" });
      const data = JSON.parse(response.content[0].text);

      expect(data.query).toBe("authentication");
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results).toBeDefined();
    });

    it("should search within a specific framework", async () => {
      const response = await searchControlsHandler({ query: "access", framework: "owasp" });
      const data = JSON.parse(response.content[0].text);

      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
      expect(data.results["NIST SP 800-53"]).toBeUndefined();
    });

    it("should handle empty search results", async () => {
      const response = await searchControlsHandler({ query: "nonexistentkeyword12345", framework: "all" });
      const data = JSON.parse(response.content[0].text);

      expect(data.totalMatches).toBe(0);
      expect(Object.keys(data.results).length).toBe(0);
    });
  });

  describe("cveLookupHandler", () => {
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
      originalFetch = global.fetch;
    });

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it("should return CVE details on successful lookup", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id: "CVE-2021-44228", description: "Log4j vulnerability" })
      }) as any;

      const response = await cveLookupHandler({ cveId: "CVE-2021-44228" });

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
      expect(response.isError).toBeUndefined();

      const data = JSON.parse(response.content[0].text);
      expect(data.id).toBe("CVE-2021-44228");
    });

    it("should sanitize the input CVE ID", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({})
      }) as any;

      await cveLookupHandler({ cveId: "CVE-2021-44228/?invalid" });

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228%2F%3Finvalid");
    });

    it("should handle 404 not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      }) as any;

      const response = await cveLookupHandler({ cveId: "CVE-UNKNOWN" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it("should handle other API errors", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: "Internal Server Error"
      }) as any;

      const response = await cveLookupHandler({ cveId: "CVE-ERROR" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Failed to fetch");
    });

    it("should handle network exceptions", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network failure")) as any;

      const response = await cveLookupHandler({ cveId: "CVE-ERROR" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error looking up CVE: Network failure");
    });
  });

  describe("Server Startup", () => {
    it("should connect using StdioServerTransport", async () => {
      // Mock console.error to prevent logging during test
      const originalConsoleError = console.error;
      console.error = vi.fn();

      // We can test `main()` behavior directly by running it. The StdioServerTransport will connect to the process streams.
      // We check if it logged the expected success message.

      // Store original connect to avoid true side effects on our global server instance if not desired
      const originalConnect = (await import('./index.js')).server.connect;
      (await import('./index.js')).server.connect = vi.fn().mockResolvedValue(undefined);

      await main();

      expect(console.error).toHaveBeenCalledWith("🔐 security-audit-mcp server running on stdio");

      // Restore
      (await import('./index.js')).server.connect = originalConnect;
      console.error = originalConsoleError;

      // Clear mocks
      vi.clearAllMocks();
    });
  });
});
