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

describe("Handlers", () => {
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
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks.find((f: any) => f.id === "owasp")).toBeDefined();
    });
  });

  describe("handleGetFramework", () => {
    it("should return a framework if found", async () => {
      const result = await handleGetFramework({ framework: "owasp" });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe("OWASP Top 10");
    });

    it("should return an error if framework not found", async () => {
      const result = await handleGetFramework({ framework: "nonexistent" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("handleAuditItem", () => {
    it("should record a valid audit item", async () => {
      const result = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Looks good",
      });
      expect(result.isError).toBeUndefined();
      const session = sessions.get("session-1");
      expect(session).toBeDefined();
      expect(session!.results.length).toBe(1);
      expect(session!.results[0]).toMatchObject({
        itemId: "A01",
        status: "pass",
        notes: "Looks good",
      });
    });

    it("should update an existing audit item", async () => {
      await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "fail",
      });
      await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
        notes: "Fixed",
      });
      const session = sessions.get("session-1");
      expect(session!.results.length).toBe(1);
      expect(session!.results[0].status).toBe("pass");
      expect(session!.results[0].notes).toBe("Fixed");
    });

    it("should return error if item not found", async () => {
      const result = await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "nonexistent",
        status: "pass",
      });
      expect(result.isError).toBe(true);
    });

    it("should return error if framework not found", async () => {
        const result = await handleAuditItem({
          sessionId: "session-1",
          framework: "invalidfw",
          itemId: "A01",
          status: "pass",
        });
        expect(result.isError).toBe(true);
      });
  });

  describe("handleGenerateReport", () => {
    beforeEach(async () => {
      await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A01",
        status: "pass",
      });
      await handleAuditItem({
        sessionId: "session-1",
        framework: "owasp",
        itemId: "A02",
        status: "fail",
      });
    });

    it("should generate a JSON report", async () => {
      const result = await handleGenerateReport({ sessionId: "session-1", format: "json" });
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe("session-1");
      expect(data.score).toBe("50%");
      expect(data.summary).toMatchObject({ passed: 1, failed: 1, skipped: 0 });
    });

    it("should generate a Markdown report", async () => {
      const result = await handleGenerateReport({ sessionId: "session-1", format: "markdown" });
      expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
      expect(result.content[0].text).toContain("Score:** 50%");
    });

    it("should generate an HTML report", async () => {
      const result = await handleGenerateReport({ sessionId: "session-1", format: "html" });
      expect(result.content[0].text).toContain("<!DOCTYPE html>");
      expect(result.content[0].text).toContain("50%");
    });

    it("should return error if session not found", async () => {
      const result = await handleGenerateReport({ sessionId: "nonexistent", format: "json" });
      expect(result.isError).toBe(true);
    });

    it("should return error if framework not found for session", async () => {
        sessions.set("session-invalid", { id: "session-invalid", framework: "invalidfw", results: [], startedAt: new Date().toISOString() });
        const result = await handleGenerateReport({ sessionId: "session-invalid", format: "json" });
        expect(result.isError).toBe(true);
      });
  });

  describe("handleGetRiskSummary", () => {
    it("should summarize risks for a framework", async () => {
      const result = await handleGetRiskSummary({ framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });

    it("should return error if framework not found", async () => {
      const result = await handleGetRiskSummary({ framework: "nonexistent" });
      expect(result.isError).toBe(true);
    });
  });

  describe("handleSearchControls", () => {
    it("should search controls across all frameworks", async () => {
      const result = await handleSearchControls({ query: "injection", framework: "all" });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["OWASP Top 10"]).toBeDefined();
    });

    it("should search controls within a specific framework", async () => {
      const result = await handleSearchControls({ query: "access", framework: "owasp" });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results["NIST SP 800-53"]).toBeUndefined();
    });
  });

  describe("handleCveLookup", () => {
    it("should successfully look up a CVE", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id: "CVE-1234-5678", summary: "Test vulnerability" }),
      } as any);

      const result = await handleCveLookup({ cveId: "CVE-1234-5678" });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe("CVE-1234-5678");
    });

    it("should return error if CVE not found (404)", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      } as any);

      const result = await handleCveLookup({ cveId: "CVE-UNKNOWN" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it("should handle fetch errors gracefully", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

      const result = await handleCveLookup({ cveId: "CVE-1234-5678" });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Network Error");
    });
  });
});
