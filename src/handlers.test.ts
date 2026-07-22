import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
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

describe("Tool Handlers", () => {
  beforeEach(() => {
    sessions.clear();
  });

  describe("handleListFrameworks", () => {
    it("should return a list of frameworks", async () => {
      const response = await handleListFrameworks();
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks.find((f: any) => f.id === "owasp")).toBeDefined();
      expect(data.frameworks.find((f: any) => f.id === "pcidss")).toBeDefined();
    });
  });

  describe("handleGetFramework", () => {
    it("should return framework details for an existing framework", async () => {
      const response = await handleGetFramework({ framework: "owasp" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
      expect(data.items.length).toBeGreaterThan(0);
    });

    it("should return error for non-existent framework", async () => {
      const response = await handleGetFramework({ framework: "invalid_framework" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe("handleAuditItem", () => {
    it("should record an audit item successfully", async () => {
      const response = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good"
      });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.itemId).toBe("A01");
      expect(data.recorded.status).toBe("pass");

      const session = sessions.get("session-1");
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
    });

    it("should return error for invalid framework", async () => {
      const response = await handleAuditItem({
        sessionId: "session-1",
        framework: "invalid",
        itemId: "A01",
        status: "pass"
      });
      expect(response.isError).toBe(true);
    });

    it("should return error for invalid item ID", async () => {
      const response = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "INVALID-ITEM",
        status: "pass"
      });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleGenerateReport", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2023-10-01T12:00:00.000Z"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("should generate a JSON report successfully", async () => {
      await handleAuditItem({ sessionId: "test-session", framework: "owasp", itemId: "A01", status: "pass" });
      await handleAuditItem({ sessionId: "test-session", framework: "owasp", itemId: "A02", status: "fail" });

      const response = await handleGenerateReport({ sessionId: "test-session", format: "json" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe("test-session");
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.score).toBe("50%");
    });

    it("should generate a markdown report successfully", async () => {
      await handleAuditItem({ sessionId: "test-session", framework: "owasp", itemId: "A01", status: "pass" });
      const response = await handleGenerateReport({ sessionId: "test-session", format: "markdown" });
      expect(response.content[0].type).toBe("text");
      expect(response.content[0].text).toContain("Score:** 100%");
      expect(response.content[0].text).toContain("| A01 |");
    });

    it("should generate a HTML report successfully", async () => {
      await handleAuditItem({ sessionId: "test-session", framework: "owasp", itemId: "A01", status: "pass" });
      const response = await handleGenerateReport({ sessionId: "test-session", format: "html" });
      expect(response.content[0].type).toBe("text");
      expect(response.content[0].text).toContain("<!DOCTYPE html>");
      expect(response.content[0].text).toContain("100%");
    });

    it("should return error for non-existent session", async () => {
      const response = await handleGenerateReport({ sessionId: "invalid", format: "json" });
      expect(response.isError).toBe(true);
    });
  });

  describe("handleGetRiskSummary", () => {
    it("should return a risk summary for a framework", async () => {
      const response = await handleGetRiskSummary({ framework: "owasp" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(data.riskBreakdown.HIGH).toBeDefined();
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });

    it("should return an error for invalid framework", async () => {
       const response = await handleGetRiskSummary({ framework: "invalid_framework" });
       expect(response.isError).toBe(true);
    });
  });

  describe("handleSearchControls", () => {
    it("should search controls across all frameworks", async () => {
      const response = await handleSearchControls({ query: "injection", framework: "all" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });

    it("should search controls within a specific framework", async () => {
      const response = await handleSearchControls({ query: "access control", framework: "nist" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.results["NIST SP 800-53"]).toBeDefined();
      expect(data.results["OWASP Top 10"]).toBeUndefined();
    });
  });

  describe("handleCveLookup", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    it("should return CVE data successfully", async () => {
      const mockCveData = {
        cveMetadata: {
          cveId: "CVE-2021-44228",
        },
        containers: {
          cna: {
            descriptions: [{ value: "Apache Log4j2 vulnerability" }],
          },
        },
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockCveData,
      } as Response);

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(response.content[0].type).toBe("text");
      const data = JSON.parse(response.content[0].text);
      expect(data.cveMetadata.cveId).toBe("CVE-2021-44228");

      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("should return error when fetch fails", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: "Not Found",
      } as Response);

      const response = await handleCveLookup({ cveId: "CVE-UNKNOWN" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Failed to fetch CVE data: 404 Not Found");
    });

    it("should handle exceptions during fetch", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

      const response = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("Error fetching CVE data: Network Error");
    });
  });
});