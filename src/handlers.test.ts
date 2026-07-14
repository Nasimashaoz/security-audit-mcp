import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup,
  sessions,
} from "./handlers.js";

describe("handlers", () => {
  beforeEach(() => {
    sessions.clear();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe("handleListFrameworks", () => {
    it("should list all available frameworks", async () => {
      const response = await handleListFrameworks();
      const content = JSON.parse(response.content[0].text);
      expect(content.frameworks.length).toBeGreaterThan(0);
      expect(content.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
      expect(content.frameworks.some((f: any) => f.id === "gdpr")).toBe(true);
    });
  });

  describe("handleGetFramework", () => {
    it("should return the requested framework", async () => {
      const response = await handleGetFramework({ framework: "owasp" });
      const content = JSON.parse(response.content[0].text);
      expect(content.name).toBe("OWASP Top 10");
      expect(content.items.length).toBeGreaterThan(0);
    });

    it("should return an error for an invalid framework", async () => {
      const response = await handleGetFramework({ framework: "invalid_framework" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("handleAuditItem", () => {
    it("should record an audit result", async () => {
      const response = await handleAuditItem({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good",
      });
      const content = JSON.parse(response.content[0].text);
      expect(content.recorded.itemId).toBe("A01");
      expect(content.recorded.status).toBe("pass");

      const session = sessions.get("test-session");
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
    });

    it("should handle invalid item", async () => {
      const response = await handleAuditItem({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "INVALID-ITEM",
        status: "pass",
      });
      expect(response.isError).toBe(true);
    });

     it("should handle invalid framework", async () => {
      const response = await handleAuditItem({
        sessionId: "test-session",
        framework: "invalid",
        itemId: "A01",
        status: "pass",
      });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleGenerateReport", () => {
    beforeEach(async () => {
      await handleAuditItem({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Missing access controls",
      });
      await handleAuditItem({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A02",
        status: "pass",
      });
    });

    it("should generate a JSON report", async () => {
      const response = await handleGenerateReport({ sessionId: "test-session", format: "json" });
      const content = JSON.parse(response.content[0].text);
      expect(content.session).toBe("test-session");
      expect(content.summary.failed).toBe(1);
      expect(content.summary.passed).toBe(1);
    });

    it("should generate a markdown report", async () => {
      const response = await handleGenerateReport({ sessionId: "test-session", format: "markdown" });
      expect(response.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(response.content[0].text).toContain("Missing access controls");
    });

    it("should return an error for unknown session", async () => {
        const response = await handleGenerateReport({ sessionId: "unknown", format: "json" });
        expect(response.isError).toBe(true);
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should provide risk summary for a framework", async () => {
      const response = await handleGetRiskSummary({ framework: "owasp" });
      const content = JSON.parse(response.content[0].text);
      expect(content.framework).toBe("OWASP Top 10");
      expect(content.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });

    it("should return an error for an unknown framework", async () => {
        const response = await handleGetRiskSummary({ framework: "unknown" });
        expect(response.isError).toBe(true);
    });
  });

  describe("handleSearchControls", () => {
    it("should search controls across all frameworks", async () => {
      const response = await handleSearchControls({ query: "authentication", framework: "all" });
      const content = JSON.parse(response.content[0].text);
      expect(content.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(content.results).length).toBeGreaterThan(0);
    });

    it("should search controls within a specific framework", async () => {
        const response = await handleSearchControls({ query: "access", framework: "owasp" });
        const content = JSON.parse(response.content[0].text);
        expect(content.results["OWASP Top 10"]).toBeDefined();
    });
  });

  describe("handleCveLookup", () => {
    it("should fetch and format CVE data", async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({
          cveMetadata: { cveId: "CVE-2024-1234", state: "PUBLISHED" },
          containers: {
            cna: {
              title: "Test Vulnerability",
              descriptions: [{ value: "A test description" }],
              metrics: [{ cvssV3_1: { version: "3.1", baseScore: 9.8, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }]
            }
          }
        })
      };
      global.fetch = vi.fn().mockResolvedValue(mockResponse as any);

      const response = await handleCveLookup({ cveId: "CVE-2024-1234" });
      const content = JSON.parse(response.content[0].text);

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2024-1234");
      expect(content.cveId).toBe("CVE-2024-1234");
      expect(content.title).toBe("Test Vulnerability");
      expect(content.cvss.baseScore).toBe(9.8);
    });

    it("should handle fetch errors", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

      const response = await handleCveLookup({ cveId: "CVE-2024-1234" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error fetching CVE data");
    });

    it("should handle non-ok http responses", async () => {
        global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 });

        const response = await handleCveLookup({ cveId: "CVE-UNKNOWN" });
        expect(response.isError).toBe(true);
        expect(response.content[0].text).toContain("HTTP 404");
    });

    it("should sanitize input for URLs", async () => {
        global.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });

        await handleCveLookup({ cveId: "CVE-2024-1234/test" });
        expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2024-1234%2Ftest");
    });
  });
});
