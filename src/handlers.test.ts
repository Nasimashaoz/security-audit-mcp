import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup
} from "./handlers.js";
import { clearSessions } from "./state.js";
import { FRAMEWORKS } from "./frameworks.js";

describe("Handlers", () => {
  beforeEach(() => {
    clearSessions();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  describe("handleListFrameworks", () => {
    it("should return a list of all frameworks", async () => {
      const response = await handleListFrameworks();
      expect(response).toHaveProperty("content");
      const contentText = response.content[0].text;
      const parsedContent = JSON.parse(contentText);

      expect(parsedContent).toHaveProperty("frameworks");
      expect(parsedContent.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(parsedContent.frameworks[0]).toHaveProperty("id", "owasp");
    });
  });

  describe("handleGetFramework", () => {
    it("should return the specified framework", async () => {
      const response = await handleGetFramework({ framework: "owasp" });
      expect(response).toHaveProperty("content");
      const parsedContent = JSON.parse(response.content[0].text);
      expect(parsedContent).toHaveProperty("name", "OWASP Top 10");
    });

    it("should return an error for non-existent framework", async () => {
      const response = await handleGetFramework({ framework: "invalid_framework" });
      expect(response).toHaveProperty("isError", true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("handleAuditItem", () => {
    it("should record an audit result", async () => {
      const response = await handleAuditItem({
        sessionId: "test_session",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });

      expect(response).not.toHaveProperty("isError");
      const parsedContent = JSON.parse(response.content[0].text);
      expect(parsedContent).toHaveProperty("recorded");
      expect(parsedContent.recorded).toEqual({
        itemId: "A01",
        title: "Broken Access Control",
        risk: "CRITICAL",
        status: "pass",
        notes: "Looks good"
      });
    });

    it("should return error for invalid framework", async () => {
      const response = await handleAuditItem({
        sessionId: "test_session",
        framework: "invalid",
        itemId: "A01",
        status: "pass"
      });
      expect(response.isError).toBe(true);
    });

    it("should return error for invalid itemId", async () => {
      const response = await handleAuditItem({
        sessionId: "test_session",
        framework: "owasp",
        itemId: "INVALID_ID",
        status: "pass"
      });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleGenerateReport", () => {
    it("should generate a markdown report successfully", async () => {
      // First create a session
      await handleAuditItem({
        sessionId: "test_session",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
        notes: "Needs fixing"
      });

      const response = await handleGenerateReport({ sessionId: "test_session", format: "markdown" });
      expect(response).not.toHaveProperty("isError");
      expect(response.content[0].type).toBe("text");
      expect(response.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(response.content[0].text).toContain("## 🚨 Critical Findings");
      expect(response.content[0].text).toContain("A01");
    });

    it("should generate a json report successfully", async () => {
      await handleAuditItem({
        sessionId: "test_session_json",
        framework: "owasp",
        itemId: "A01",
        status: "pass"
      });

      const response = await handleGenerateReport({ sessionId: "test_session_json", format: "json" });
      expect(response).not.toHaveProperty("isError");
      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe("test_session_json");
      expect(data.score).toBe("100%");
      expect(data.summary.passed).toBe(1);
    });

    it("should generate an html report successfully", async () => {
       await handleAuditItem({
        sessionId: "test_session_html",
        framework: "owasp",
        itemId: "A01",
        status: "pass"
      });

      const response = await handleGenerateReport({ sessionId: "test_session_html", format: "html" });
      expect(response).not.toHaveProperty("isError");
      expect(response.content[0].text).toContain("<!DOCTYPE html>");
      expect(response.content[0].text).toContain("🔒 Security Audit Report");
    });


    it("should return error for non-existent session", async () => {
      const response = await handleGenerateReport({ sessionId: "missing_session", format: "json" });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should return a risk summary for a valid framework", async () => {
      const response = await handleGetRiskSummary({ framework: "owasp" });
      expect(response).not.toHaveProperty("isError");
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
      const response = await handleSearchControls({ query: "encrypted", framework: "all" });
      const data = JSON.parse(response.content[0].text);
      expect(data.query).toBe("encrypted");
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results).toHaveProperty("OWASP Top 10");
    });

    it("should search controls within a specific framework", async () => {
      const response = await handleSearchControls({ query: "encrypted", framework: "owasp" });
      const data = JSON.parse(response.content[0].text);
      expect(data.query).toBe("encrypted");
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results).toHaveProperty("OWASP Top 10");
      expect(Object.keys(data.results).length).toBe(1);
    });
  });

  describe("handleCveLookup", () => {
    it("should return data on successful fetch", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id: "CVE-2021-44228", description: "Log4j" })
      });
      vi.stubGlobal('fetch', mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(response).not.toHaveProperty("isError");

      const data = JSON.parse(response.content[0].text);
      expect(data.id).toBe("CVE-2021-44228");

      // Ensure encodeURIComponent was used correctly
      expect(mockFetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should encode URI components in cveId correctly", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id: "CVE-TEST", description: "Test" })
      });
      vi.stubGlobal('fetch', mockFetch);

      await handleCveLookup({ cveId: "CVE-TEST/123" });
      // Ensure encodeURIComponent was used correctly
      expect(mockFetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-TEST%2F123");
    });

    it("should handle failed fetch gracefully", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        statusText: "Not Found"
      });
      vi.stubGlobal('fetch', mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-INVALID" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Failed to fetch CVE data");
    });

    it("should handle fetch error exception", async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error("Network Error"));
      vi.stubGlobal('fetch', mockFetch);

      const response = await handleCveLookup({ cveId: "CVE-1234" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error fetching CVE data: Network Error");
    });
  });
});
