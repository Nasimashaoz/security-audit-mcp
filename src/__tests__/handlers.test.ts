import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { clearSessions } from "../state.js";
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup
} from "../handlers.js";

describe("Handlers", () => {
  beforeEach(() => {
    clearSessions();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  describe("handleListFrameworks", () => {
    it("should list available frameworks", async () => {
      const response = await handleListFrameworks();
      expect(response.content[0].type).toBe("text");

      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks).toBeInstanceOf(Array);
      expect(data.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
      expect(data.frameworks.some((f: any) => f.id === "pcidss")).toBe(true);
    });
  });

  describe("handleGetFramework", () => {
    it("should return a framework if it exists", async () => {
      const response = await handleGetFramework({ framework: "owasp" });
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
    });

    it("should return an error for unknown framework", async () => {
      const response = await handleGetFramework({ framework: "unknown" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("handleAuditItem", () => {
    it("should record an audit item successfully", async () => {
      const response = await handleAuditItem({
        sessionId: "s1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Missing control"
      });
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("fail");
    });

    it("should error for unknown framework", async () => {
      const response = await handleAuditItem({
        sessionId: "s1",
        framework: "unknown",
        itemId: "A01",
        status: "pass"
      });
      expect(response.isError).toBe(true);
    });

    it("should error for unknown item ID", async () => {
      const response = await handleAuditItem({
        sessionId: "s1",
        framework: "owasp",
        itemId: "UNKNOWN_ID",
        status: "pass"
      });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleGenerateReport", () => {
    beforeEach(async () => {
      await handleAuditItem({
        sessionId: "s1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Missing control"
      });
    });

    it("should generate a JSON report", async () => {
      const response = await handleGenerateReport({ sessionId: "s1", format: "json" });
      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe("s1");
      expect(data.framework).toBe("OWASP Top 10");
      expect(data.summary.failed).toBe(1);
    });

    it("should generate a markdown report", async () => {
      const response = await handleGenerateReport({ sessionId: "s1", format: "markdown" });
      expect(response.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(response.content[0].text).toContain("OWASP Top 10");
    });

    it("should generate an HTML report", async () => {
      const response = await handleGenerateReport({ sessionId: "s1", format: "html" });
      expect(response.content[0].text).toContain("<!DOCTYPE html>");
      expect(response.content[0].text).toContain("OWASP Top 10");
    });

    it("should return error for unknown session", async () => {
      const response = await handleGenerateReport({ sessionId: "unknown", format: "json" });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should return a risk summary for a valid framework", async () => {
      const response = await handleGetRiskSummary({ framework: "owasp" });
      const data = JSON.parse(response.content[0].text);
      expect(data.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
      expect(data.riskBreakdown.HIGH).toBeInstanceOf(Array);
    });

    it("should return error for unknown framework", async () => {
      const response = await handleGetRiskSummary({ framework: "unknown" });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleSearchControls", () => {
    it("should search controls across all frameworks", async () => {
      const response = await handleSearchControls({ query: "authentication", framework: "all" });
      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
    });

    it("should search controls within a specific framework", async () => {
      const response = await handleSearchControls({ query: "authentication", framework: "owasp" });
      const data = JSON.parse(response.content[0].text);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });
  });

  describe("handleCveLookup", () => {
    it("should successfully lookup a CVE", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          cveMetadata: { cveId: "CVE-2021-44228", state: "PUBLISHED" },
          containers: {
            cna: {
              descriptions: [{ value: "Log4j vulnerability" }],
              metrics: [{ cvssV3_1: { baseScore: 10.0, baseSeverity: "CRITICAL" } }]
            }
          }
        })
      });
      vi.stubGlobal("fetch", mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      const data = JSON.parse(response.content[0].text);

      expect(data.cveId).toBe("CVE-2021-44228");
      expect(data.cvssScore).toBe(10.0);
      expect(data.description).toBe("Log4j vulnerability");
    });

    it("should handle 404 not found", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      });
      vi.stubGlobal("fetch", mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-UNKNOWN" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it("should handle other fetch errors", async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("Network error"));
      vi.stubGlobal("fetch", mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Failed to fetch CVE data: Network error");
    });
  });
});
