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

describe("Handlers", () => {
  beforeEach(() => {
    sessions.clear();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("handleListFrameworks", () => {
    it("should list all frameworks", async () => {
      const result = await handleListFrameworks();
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(data.frameworks[0]).toHaveProperty("id");
      expect(data.frameworks[0]).toHaveProperty("name");
      expect(data.frameworks[0]).toHaveProperty("version");
    });
  });

  describe("handleGetFramework", () => {
    it("should return the specified framework", async () => {
      const result = await handleGetFramework({ framework: "owasp" });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items.length).toBeGreaterThan(0);
    });

    it("should return error for unknown framework", async () => {
      const result = await handleGetFramework({ framework: "unknown" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("handleAuditItem", () => {
    it("should record an audit item successfully", async () => {
      const result = await handleAuditItem({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");

      const session = sessions.get("test-session");
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
    });

    it("should update existing audit item", async () => {
      await handleAuditItem({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A01",
        status: "pass"
      });
      const result = await handleAuditItem({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Failed now"
      });
      const session = sessions.get("test-session");
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].status).toBe("fail");
    });

    it("should return error for unknown framework", async () => {
      const result = await handleAuditItem({
        sessionId: "test-session",
        framework: "unknown",
        itemId: "A01",
        status: "pass"
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Framework 'unknown' not found");
    });

    it("should return error for unknown item", async () => {
      const result = await handleAuditItem({
        sessionId: "test-session",
        framework: "owasp",
        itemId: "unknown",
        status: "pass"
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Item 'unknown' not found");
    });
  });

  describe("handleGenerateReport", () => {
    beforeEach(async () => {
      await handleAuditItem({ sessionId: "test-session", framework: "owasp", itemId: "A01", status: "pass" });
      await handleAuditItem({ sessionId: "test-session", framework: "owasp", itemId: "A02", status: "fail", notes: "Bad crypto" });
      await handleAuditItem({ sessionId: "test-session", framework: "owasp", itemId: "A08", status: "skip" });
    });

    it("should return error for unknown session", async () => {
      const result = await handleGenerateReport({ sessionId: "unknown", format: "json" });
      expect(result.isError).toBe(true);
    });

    it("should generate JSON report", async () => {
      const result = await handleGenerateReport({ sessionId: "test-session", format: "json" });
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe("test-session");
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.summary.skipped).toBe(1);
      expect(data.score).toBe("33%");
    });

    it("should generate markdown report", async () => {
      const result = await handleGenerateReport({ sessionId: "test-session", format: "markdown" });
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("Score:** 33%");
    });

    it("should generate HTML report", async () => {
      const result = await handleGenerateReport({ sessionId: "test-session", format: "html" });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("33%");
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should get risk summary", async () => {
      const result = await handleGetRiskSummary({ framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });

    it("should return error for unknown framework", async () => {
      const result = await handleGetRiskSummary({ framework: "unknown" });
      expect(result.isError).toBe(true);
    });
  });

  describe("handleSearchControls", () => {
    it("should search controls in a specific framework", async () => {
      const result = await handleSearchControls({ query: "injection", framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });

    it("should search controls across all frameworks", async () => {
      const result = await handleSearchControls({ query: "access", framework: "all" });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });
  });

  describe("handleCveLookup", () => {
    beforeEach(() => {
      global.fetch = vi.fn() as any;
    });

    it("should return CVE details on success", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ cveMetadata: { cveId: "CVE-2021-44228" } })
      });
      const result = await handleCveLookup({ cveId: "CVE-2021-44228" });
      const data = JSON.parse(result.content[0].text);
      expect(data.cveMetadata.cveId).toBe("CVE-2021-44228");
    });

    it("should return error on 404", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404
      });
      const result = await handleCveLookup({ cveId: "UNKNOWN" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should return error on API failure", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500
      });
      const result = await handleCveLookup({ cveId: "CVE-123" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch");
    });

    it("should handle exceptions", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network Error"));
      const result = await handleCveLookup({ cveId: "CVE-123" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error looking up CVE: Network Error");
    });
  });
});
