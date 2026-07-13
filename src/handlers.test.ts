import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup,
  sessions
} from "./handlers.js";
import { FRAMEWORKS } from "./frameworks.js";

describe("Framework Handlers", () => {
  beforeEach(() => {
    sessions.clear();
  });

  describe("handleListFrameworks", () => {
    it("should return a list of all frameworks", async () => {
      const response = await handleListFrameworks();
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(data.frameworks.find((f: any) => f.id === "owasp")).toBeDefined();
    });
  });

  describe("handleGetFramework", () => {
    it("should return framework details for a valid framework", async () => {
      const response = await handleGetFramework({ framework: "owasp" });
      expect(response.isError).toBeUndefined();
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
    });

    it("should return an error for an invalid framework", async () => {
      const response = await handleGetFramework({ framework: "invalid_fw" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });
  describe("handleAuditItem", () => {
    it("should successfully record a pass result for an item", async () => {
      const response = await handleAuditItem({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });
      expect(response.isError).toBeUndefined();

      const session = sessions.get("test-session-1");
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].itemId).toBe("A01");
      expect(session?.results[0].status).toBe("pass");

      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
    });

    it("should update an existing result for the same item", async () => {
      await handleAuditItem({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });
      await handleAuditItem({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Failed on re-check"
      });

      const session = sessions.get("test-session-1");
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].status).toBe("fail");
    });

    it("should return an error for an invalid item ID", async () => {
      const response = await handleAuditItem({
        sessionId: "test-session-2",
        framework: "owasp",
        itemId: "INVALID",
        status: "pass"
      });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("handleSearchControls", () => {
    it("should search across all frameworks by default", async () => {
      const response = await handleSearchControls({ query: "authentication", framework: "all" });
      const data = JSON.parse(response.content[0].text);

      expect(data.query).toBe("authentication");
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });

    it("should search within a specific framework", async () => {
      const response = await handleSearchControls({ query: "encrypted", framework: "owasp" });
      const data = JSON.parse(response.content[0].text);

      expect(data.results["OWASP Top 10"]).toBeDefined();
      expect(data.results["NIST SP 800-53"]).toBeUndefined();
    });
  });

  describe("handleGenerateReport", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2023-01-01T12:00:00.000Z"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("should generate a JSON report", async () => {
      // Seed a session
      sessions.set("report-session", {
        id: "report-session",
        framework: "owasp",
        results: [
          { itemId: "A01", title: "Broken Access Control", risk: "CRITICAL", status: "pass", notes: "" },
          { itemId: "A02", title: "Cryptographic Failures", risk: "CRITICAL", status: "fail", notes: "Missing encryption" }
        ],
        startedAt: new Date().toISOString()
      });

      const response = await handleGenerateReport({ sessionId: "report-session", format: "json" });
      const data = JSON.parse(response.content[0].text);

      expect(data.score).toBe("50%");
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.generatedAt).toBe("2023-01-01T12:00:00.000Z");
    });

    it("should generate a markdown report", async () => {
      sessions.set("report-session", {
        id: "report-session",
        framework: "owasp",
        results: [
          { itemId: "A01", title: "Broken Access Control", risk: "CRITICAL", status: "pass", notes: "" },
        ],
        startedAt: new Date().toISOString()
      });

      const response = await handleGenerateReport({ sessionId: "report-session", format: "markdown" });
      const text = response.content[0].text;

      expect(text).toContain("# 🔒 Security Audit Report");
      expect(text).toContain("**Score:** 100%");
      expect(text).toContain("| A01 | Broken Access Control | CRITICAL | PASS |  |");
    });

    it("should handle session not found", async () => {
      const response = await handleGenerateReport({ sessionId: "invalid-session", format: "json" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("handleCveLookup", () => {
    let fetchMock: any;

    beforeEach(() => {
      fetchMock = vi.fn();
      global.fetch = fetchMock;
    });

    it("should reject an invalid CVE ID", async () => {
      const response = await handleCveLookup({ cveId: "CVE-21-44228" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Invalid CVE ID format");
    });

    it("should successfully fetch CVE data", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ id: "CVE-2021-44228", description: "Log4j" })
      });

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(response.isError).toBeUndefined();

      const data = JSON.parse(response.content[0].text);
      expect(data.id).toBe("CVE-2021-44228");
      expect(fetchMock).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle CVE not found", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      const response = await handleCveLookup({ cveId: "CVE-1999-99999" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found in the MITRE database");
    });

    it("should handle fetch failure", async () => {
      fetchMock.mockRejectedValueOnce(new Error("Network Error"));

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Network Error");
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should return risk breakdown for a framework", async () => {
      const response = await handleGetRiskSummary({ framework: "owasp" });
      const data = JSON.parse(response.content[0].text);

      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown).toBeDefined();
      expect(data.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
      expect(data.riskBreakdown.HIGH).toBeInstanceOf(Array);

      // OWASP A01 is CRITICAL
      expect(data.riskBreakdown.CRITICAL.some((item: string) => item.includes("A01"))).toBe(true);
    });
  });
});
