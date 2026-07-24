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

describe("Handlers", () => {
  beforeEach(() => {
    sessions.clear();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T12:00:00Z"));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("should list frameworks", async () => {
    const res = await handleListFrameworks();
    expect(res.content[0].type).toBe("text");
    const data = JSON.parse(res.content[0].text);
    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.length).toBeGreaterThan(0);
    expect(data.frameworks[0].id).toBe("owasp");
  });

  it("should get a specific framework", async () => {
    const res = await handleGetFramework({ framework: "owasp" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
  });

  it("should handle get unknown framework", async () => {
    const res = await handleGetFramework({ framework: "unknown" });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain("not found");
  });

  it("should audit an item and generate report", async () => {
    const auditRes = await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "Fixed issue"
    });

    expect(auditRes.isError).toBeUndefined();

    const reportRes = await handleGenerateReport({
      sessionId: "test-session",
      format: "json"
    });
    expect(reportRes.isError).toBeUndefined();

    const reportData = JSON.parse(reportRes.content[0].text);
    expect(reportData.score).toBe("100%");
    expect(reportData.summary.passed).toBe(1);
    expect(reportData.generatedAt).toBe("2024-01-01T12:00:00.000Z");
  });

  it("should generate markdown and html reports", async () => {
    await handleAuditItem({
      sessionId: "test-session-2",
      framework: "nist",
      itemId: "AC-1",
      status: "fail",
      notes: "Need policy"
    });

    const mdRes = await handleGenerateReport({
      sessionId: "test-session-2",
      format: "markdown"
    });
    expect(mdRes.content[0].text).toContain("🔒 Security Audit Report");
    expect(mdRes.content[0].text).toContain("Need policy");

    const htmlRes = await handleGenerateReport({
      sessionId: "test-session-2",
      format: "html"
    });
    expect(htmlRes.content[0].text).toContain("<!DOCTYPE html>");
    expect(htmlRes.content[0].text).toContain("Need policy");
  });

  it("should get risk summary", async () => {
    const res = await handleGetRiskSummary({ framework: "owasp" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("should search controls", async () => {
    const res = await handleSearchControls({ query: "injection", framework: "all" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results["OWASP Top 10"]).toBeDefined();
  });

  describe("cve_lookup", () => {
    it("should fetch CVE data successfully", async () => {
      const mockData = { id: "CVE-2021-44228", description: "Log4j vulnerability" };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockData
      }) as any;

      const res = await handleCveLookup({ cveId: "CVE-2021-44228" });
      expect(res.isError).toBeUndefined();
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
      expect(JSON.parse(res.content[0].text)).toEqual(mockData);
    });

    it("should handle 404 correctly", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      }) as any;

      const res = await handleCveLookup({ cveId: "CVE-UNKNOWN" });
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("not found");
    });

    it("should sanitize URL input", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({})
      }) as any;

      await handleCveLookup({ cveId: "CVE-2021-44228?param=value" });
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228%3Fparam%3Dvalue");
    });
  });
});
