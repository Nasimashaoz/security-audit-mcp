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
    vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe("handleListFrameworks", () => {
    it("should list all frameworks", async () => {
      const result = await handleListFrameworks();
      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks.length).toBeGreaterThan(0);
      expect(parsed.frameworks.find((f: any) => f.id === "owasp")).toBeDefined();
    });
  });

  describe("handleGetFramework", () => {
    it("should get a valid framework", async () => {
      const result = await handleGetFramework({ framework: "owasp" });
      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe("OWASP Top 10");
      expect(parsed.items.length).toBeGreaterThan(0);
    });

    it("should handle invalid framework", async () => {
      const result = await handleGetFramework({ framework: "invalid_framework" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("handleAuditItem", () => {
    it("should record an audit item successfully", async () => {
      const result = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "test note",
      });
      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.status).toBe("fail");

      const session = sessions.get("session-1");
      expect(session).toBeDefined();
      expect(session?.results[0].itemId).toBe("A01");
      expect(session?.results[0].notes).toBe("test note");
    });

    it("should update an existing audit item", async () => {
      await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
      });
      const result = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "fixed",
      });

      const session = sessions.get("session-1");
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].status).toBe("pass");
      expect(session?.results[0].notes).toBe("fixed");
    });

    it("should return error for invalid item id", async () => {
      const result = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "INVALID-ID",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("handleGenerateReport", () => {
    beforeEach(async () => {
      await handleAuditItem({ sessionId: "session-1", framework: "owasp", itemId: "A01", status: "pass" });
      await handleAuditItem({ sessionId: "session-1", framework: "owasp", itemId: "A02", status: "fail", notes: "Bad crypto" });
      await handleAuditItem({ sessionId: "session-1", framework: "owasp", itemId: "A03", status: "skip" });
    });

    it("should generate json report", async () => {
      const result = await handleGenerateReport({ sessionId: "session-1", format: "json" });
      expect(result.content[0].type).toBe("text");
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.score).toBe("33%");
      expect(parsed.summary).toEqual({ passed: 1, failed: 1, skipped: 1 });
      expect(parsed.generatedAt).toBe("2024-01-01T00:00:00.000Z");
    });

    it("should generate markdown report", async () => {
      const result = await handleGenerateReport({ sessionId: "session-1", format: "markdown" });
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("**Score:** 33%");
      expect(result.content[0].text).toContain("## 🚨 Critical Findings");
      expect(result.content[0].text).toContain("Bad crypto");
    });

    it("should generate html report", async () => {
      const result = await handleGenerateReport({ sessionId: "session-1", format: "html" });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("<div class=\"score\">33%</div>");
    });

    it("should handle invalid session", async () => {
      const result = await handleGenerateReport({ sessionId: "invalid-session", format: "json" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should summarize risks", async () => {
      const result = await handleGetRiskSummary({ framework: "owasp" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(parsed.riskBreakdown.HIGH.length).toBeGreaterThan(0);
    });
  });

  describe("handleSearchControls", () => {
    it("should search across all frameworks", async () => {
      const result = await handleSearchControls({ query: "encrypt", framework: "all" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(parsed.results["OWASP Top 10"]).toBeDefined();
    });

    it("should search in specific framework", async () => {
      const result = await handleSearchControls({ query: "encrypt", framework: "nist" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(parsed.results["OWASP Top 10"]).toBeUndefined();
      expect(parsed.results["NIST SP 800-53"]).toBeDefined();
    });
  });

  describe("handleCveLookup", () => {
    it("should fetch CVE successfully", async () => {
      const mockData = { cveMetadata: { cveId: "CVE-2021-44228" } };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData),
      });

      const result = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
      expect(result.content[0].type).toBe("text");
      expect(JSON.parse(result.content[0].text)).toEqual(mockData);
    });

    it("should handle CVE not found", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });

      const result = await handleCveLookup({ cveId: "INVALID-CVE" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle API error status", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
      });

      const result = await handleCveLookup({ cveId: "CVE-123" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch");
    });

    it("should handle network exception", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network down"));

      const result = await handleCveLookup({ cveId: "CVE-123" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Network down");
    });
  });
});
