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
    it("returns list of frameworks", async () => {
      const result = await handleListFrameworks();
      expect(result.content[0].type).toBe("text");
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeInstanceOf(Array);
      expect(data.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
      expect(data.frameworks.some((f: any) => f.id === "gdpr")).toBe(true);
    });
  });

  describe("handleGetFramework", () => {
    it("returns framework details for valid framework", async () => {
      const result = await handleGetFramework({ framework: "owasp" });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
    });

    it("returns error for invalid framework", async () => {
      const result = await handleGetFramework({ framework: "invalid" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("handleAuditItem", () => {
    it("records a pass result successfully", async () => {
      const result = await handleAuditItem({
        sessionId: "session1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good",
      });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");
    });

    it("returns error for invalid framework", async () => {
      const result = await handleAuditItem({
        sessionId: "session1",
        framework: "invalid",
        itemId: "A01",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("returns error for invalid itemId", async () => {
      const result = await handleAuditItem({
        sessionId: "session1",
        framework: "owasp",
        itemId: "invalid_id",
        status: "pass",
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("handleGenerateReport", () => {
    beforeEach(async () => {
      await handleAuditItem({
        sessionId: "reportSession",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Critical issue",
      });
      await handleAuditItem({
        sessionId: "reportSession",
        framework: "owasp",
        itemId: "A02",
        status: "pass",
      });
    });

    it("generates markdown report by default", async () => {
      const result = await handleGenerateReport({ sessionId: "reportSession", format: "markdown" });
      expect(result.content[0].text).toContain("🔒 Security Audit Report");
      expect(result.content[0].text).toContain("50%"); // 1 pass / 2 items = 50%
    });

    it("generates json report", async () => {
      const result = await handleGenerateReport({ sessionId: "reportSession", format: "json" });
      const data = JSON.parse(result.content[0].text);
      expect(data.score).toBe("50%");
      expect(data.summary.failed).toBe(1);
      expect(data.summary.passed).toBe(1);
    });

    it("generates html report", async () => {
      const result = await handleGenerateReport({ sessionId: "reportSession", format: "html" });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("50%");
    });

    it("returns error for unknown session", async () => {
      const result = await handleGenerateReport({ sessionId: "unknown", format: "json" });
      expect(result.isError).toBe(true);
    });
  });

  describe("handleGetRiskSummary", () => {
    it("returns risk breakdown", async () => {
      const result = await handleGetRiskSummary({ framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
    });

    it("returns error for invalid framework", async () => {
      const result = await handleGetRiskSummary({ framework: "invalid" });
      expect(result.isError).toBe(true);
    });
  });

  describe("handleSearchControls", () => {
    it("searches in all frameworks", async () => {
      const result = await handleSearchControls({ query: "encryption", framework: "all" });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
    });

    it("searches in specific framework", async () => {
      const result = await handleSearchControls({ query: "cryptographic", framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });
  });

  describe("handleCveLookup", () => {
    it("fetches CVE data successfully", async () => {
      const mockData = { id: "CVE-2021-44228", description: "Log4j" };
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData),
      });
      vi.stubGlobal("fetch", mockFetch);

      const result = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(result.isError).toBeUndefined();
      expect(JSON.parse(result.content[0].text)).toEqual(mockData);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://cveawg.mitre.org/api/cve/CVE-2021-44228"
      );
    });

    it("sanitizes URL inputs", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({}),
      });
      vi.stubGlobal("fetch", mockFetch);

      await handleCveLookup({ cveId: "CVE-1234/test" });
      expect(mockFetch).toHaveBeenCalledWith(
        "https://cveawg.mitre.org/api/cve/CVE-1234%2Ftest"
      );
    });

    it("handles fetch errors", async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("Network Error"));
      vi.stubGlobal("fetch", mockFetch);

      const result = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Network Error");
    });

    it("handles non-ok responses", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        statusText: "Not Found",
      });
      vi.stubGlobal("fetch", mockFetch);

      const result = await handleCveLookup({ cveId: "CVE-9999-9999" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Not Found");
    });
  });
});
