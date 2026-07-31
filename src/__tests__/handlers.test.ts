import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGetRiskSummary,
  handleSearchControls,
  handleGenerateReport
} from "../handlers.js";
import { clearSessions } from "../state.js";

describe("Handlers", () => {
  beforeEach(() => {
    clearSessions();
  });

  describe("handleListFrameworks", () => {
    it("should list all frameworks", async () => {
      const response = await handleListFrameworks();
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks.map((f: any) => f.id)).toContain("owasp");
      expect(data.frameworks.map((f: any) => f.id)).toContain("nist");
      expect(data.frameworks.map((f: any) => f.id)).toContain("iso27001");
      expect(data.frameworks.map((f: any) => f.id)).toContain("pcidss");
      expect(data.frameworks.map((f: any) => f.id)).toContain("soc2");
      expect(data.frameworks.map((f: any) => f.id)).toContain("hipaa");
      expect(data.frameworks.map((f: any) => f.id)).toContain("cisv8");
      expect(data.frameworks.map((f: any) => f.id)).toContain("gdpr");
    });
  });

  describe("handleGetFramework", () => {
    it("should return a specific framework", async () => {
      const response = await handleGetFramework({ framework: "owasp" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
    });

    it("should return error for invalid framework", async () => {
      const response = await handleGetFramework({ framework: "invalid" });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleAuditItem", () => {
    it("should record a pass for an audit item", async () => {
      const response = await handleAuditItem({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");
      expect(data.recorded.notes).toBe("Looks good");
    });

    it("should update an existing audit item", async () => {
       await handleAuditItem({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Failed"
      });
      const response = await handleAuditItem({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Fixed"
      });
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.status).toBe("pass");
      expect(data.recorded.notes).toBe("Fixed");
    });

    it("should return error if item is not found", async () => {
      const response = await handleAuditItem({
        sessionId: "test-session-1",
        framework: "owasp",
        itemId: "INVALID-ITEM",
        status: "pass"
      });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should return risk summary for a framework", async () => {
      const response = await handleGetRiskSummary({ framework: "owasp" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
      expect(data.riskBreakdown.HIGH).toBeInstanceOf(Array);
      expect(data.riskBreakdown.MEDIUM).toBeInstanceOf(Array);
      expect(data.riskBreakdown.LOW).toBeInstanceOf(Array);
    });
  });

  describe("handleSearchControls", () => {
    it("should search controls across all frameworks", async () => {
      const response = await handleSearchControls({ query: "encrypt", framework: "all" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });

    it("should search controls within a specific framework", async () => {
      const response = await handleSearchControls({ query: "encrypt", framework: "owasp" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });
  });
});

  describe("handleGenerateReport", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("should generate a markdown report by default", async () => {
      await handleAuditItem({ sessionId: "report-session", framework: "owasp", itemId: "A01", status: "pass" });
      await handleAuditItem({ sessionId: "report-session", framework: "owasp", itemId: "A02", status: "fail", notes: "Needs fix" });

      const response = await handleGenerateReport({ sessionId: "report-session", format: "markdown" });
      expect(response.content[0].type).toBe("text");
      const text = response.content[0].text;
      expect(text).toContain("# 🔒 Security Audit Report");
      expect(text).toContain("**Score:** 50%");
      expect(text).toContain("2024-01-01T00:00:00.000Z");
      expect(text).toContain("Needs fix");
    });

    it("should generate a JSON report", async () => {
      await handleAuditItem({ sessionId: "report-session-2", framework: "nist", itemId: "AC-1", status: "skip" });

      const response = await handleGenerateReport({ sessionId: "report-session-2", format: "json" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.score).toBe("0%");
      expect(data.summary.skipped).toBe(1);
      expect(data.generatedAt).toBe("2024-01-01T00:00:00.000Z");
    });

    it("should generate an HTML report", async () => {
       await handleAuditItem({ sessionId: "report-session", framework: "iso27001", itemId: "A.5.1", status: "pass" });

       const response = await handleGenerateReport({ sessionId: "report-session", format: "html" });
       expect(response.content[0].type).toBe("text");
       const text = response.content[0].text;
       expect(text).toContain("<!DOCTYPE html>");
       expect(text).toContain("A.5.1");
    });

    it("should return error for invalid session", async () => {
      const response = await handleGenerateReport({ sessionId: "invalid-session", format: "markdown" });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleCveLookup", () => {
    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it("should fetch CVE data successfully", async () => {
      const mockCveData = { id: "CVE-2021-44228", description: "Log4Shell" };
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockCveData,
      });
      vi.stubGlobal("fetch", mockFetch);

      const { handleCveLookup } = await import("../handlers.js");
      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });

      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.id).toBe("CVE-2021-44228");
      expect(mockFetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should handle failed fetch with HTTP error", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found"
      });
      vi.stubGlobal("fetch", mockFetch);

      const { handleCveLookup } = await import("../handlers.js");
      const response = await handleCveLookup({ cveId: "CVE-UNKNOWN" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Failed to fetch CVE data for CVE-UNKNOWN: 404 Not Found");
    });

    it("should handle network error", async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("Network Error"));
      vi.stubGlobal("fetch", mockFetch);

      const { handleCveLookup } = await import("../handlers.js");
      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });

      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error looking up CVE CVE-2021-44228: Network Error");
    });
  });
