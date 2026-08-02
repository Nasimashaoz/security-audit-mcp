import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup,
} from "./handlers.js";
import { clearSessions } from "./state.js";
import { FRAMEWORKS } from "./frameworks.js";

describe("Handlers", () => {
  beforeEach(() => {
    clearSessions();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2023-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  describe("handleListFrameworks", () => {
    it("should list all frameworks", async () => {
      const response = await handleListFrameworks();
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks).toBeInstanceOf(Array);
      expect(data.frameworks.length).toBeGreaterThan(0);

      const owasp = data.frameworks.find((f: any) => f.id === "owasp");
      expect(owasp).toBeDefined();
      expect(owasp.name).toBe("OWASP Top 10");
    });
  });

  describe("handleGetFramework", () => {
    it("should return the framework checklist", async () => {
      const response = await handleGetFramework({ framework: "owasp" });
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items).toBeInstanceOf(Array);
    });

    it("should return error for unknown framework", async () => {
      const response = await handleGetFramework({ framework: "unknown" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Framework 'unknown' not found");
    });
  });

  describe("handleAuditItem", () => {
    it("should create a session and record a passing audit item", async () => {
      const response = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good",
      });
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");
      expect(data.sessionProgress).toContain("items audited");
    });

    it("should update an existing audit item result", async () => {
      await handleAuditItem({ sessionId: "session-1", framework: "owasp", itemId: "A01", status: "fail" });
      const response = await handleAuditItem({ sessionId: "session-1", framework: "owasp", itemId: "A01", status: "pass" });
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.status).toBe("pass");
      expect(data.sessionProgress).toContain("1 /"); // should still be 1 item since we updated
    });

    it("should return error for invalid framework", async () => {
      const response = await handleAuditItem({
        sessionId: "session-1",
        framework: "invalid",
        itemId: "A01",
        status: "pass",
      });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it("should return error for invalid item ID", async () => {
      const response = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "INVALID-ID",
        status: "pass",
      });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Item 'INVALID-ID' not found in owasp");
    });
  });

  describe("handleGenerateReport", () => {
    beforeEach(async () => {
      await handleAuditItem({ sessionId: "rep-session", framework: "owasp", itemId: "A01", status: "pass" });
      await handleAuditItem({ sessionId: "rep-session", framework: "owasp", itemId: "A02", status: "fail" }); // CRITICAL fail
      await handleAuditItem({ sessionId: "rep-session", framework: "owasp", itemId: "A08", status: "skip" }); // MEDIUM skip
    });

    it("should return error for unknown session", async () => {
      const response = await handleGenerateReport({ sessionId: "unknown" });
      expect(response.isError).toBe(true);
    });

    it("should generate markdown report by default", async () => {
      const response = await handleGenerateReport({ sessionId: "rep-session" });
      expect(response.content[0].text).toContain("🔒 Security Audit Report");
      expect(response.content[0].text).toContain("**Passed:** 1");
      expect(response.content[0].text).toContain("**Failed:** 1");
      expect(response.content[0].text).toContain("**Skipped:** 1");
      expect(response.content[0].text).toContain("**Score:** 33%");
      expect(response.content[0].text).toContain("🚨 Critical Findings"); // Since A02 is CRITICAL
    });

    it("should generate json report", async () => {
      const response = await handleGenerateReport({ sessionId: "rep-session", format: "json" });
      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe("rep-session");
      expect(data.summary.passed).toBe(1);
      expect(data.criticalFindings.length).toBe(1);
    });

    it("should generate html report", async () => {
      const response = await handleGenerateReport({ sessionId: "rep-session", format: "html" });
      expect(response.content[0].text).toContain("<!DOCTYPE html>");
      expect(response.content[0].text).toContain("<h1>🔒 Security Audit Report</h1>");
      expect(response.content[0].text).toContain("33%");
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should return risk summary for a framework", async () => {
      const response = await handleGetRiskSummary({ framework: "owasp" });
      const data = JSON.parse(response.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown).toHaveProperty("CRITICAL");
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });

    it("should return error for invalid framework", async () => {
      const response = await handleGetRiskSummary({ framework: "invalid" });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleSearchControls", () => {
    it("should search controls across all frameworks", async () => {
      const response = await handleSearchControls({ query: "encrypt" });
      const data = JSON.parse(response.content[0].text);
      expect(data.query).toBe("encrypt");
      expect(data.totalMatches).toBeGreaterThan(0);
      // We expect results from multiple frameworks
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });

    it("should search controls in a specific framework", async () => {
      const response = await handleSearchControls({ query: "encrypt", framework: "owasp" });
      const data = JSON.parse(response.content[0].text);
      expect(data.query).toBe("encrypt");
      expect(Object.keys(data.results).length).toBe(1); // Should only have owasp results
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });
  });

  describe("handleCveLookup", () => {
    it("should return CVE details on success", async () => {
      const mockData = { id: "CVE-2021-44228", description: "Log4j" };
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockData,
      });
      vi.stubGlobal("fetch", mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      const data = JSON.parse(response.content[0].text);
      expect(data).toEqual(mockData);
      expect(mockFetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle 404 properly", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });
      vi.stubGlobal("fetch", mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-UNKNOWN" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("CVE 'CVE-UNKNOWN' not found.");
    });

    it("should handle fetch errors", async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("Network Failure"));
      vi.stubGlobal("fetch", mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Network Failure");
    });
  });
});
