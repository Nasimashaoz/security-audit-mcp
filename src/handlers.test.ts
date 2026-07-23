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
    vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("handleListFrameworks returns frameworks", async () => {
    const result = await handleListFrameworks();
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.frameworks.length).toBeGreaterThan(0);
    expect(data.frameworks.some((fw: any) => fw.id === "owasp")).toBe(true);
  });

  it("handleGetFramework returns a framework", async () => {
    const result = await handleGetFramework({ framework: "owasp" });
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
  });

  it("handleGetFramework returns error for unknown framework", async () => {
    const result = await handleGetFramework({ framework: "unknown" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("handleAuditItem records result and creates session", async () => {
    const result = await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Test note",
    });

    expect(result.content[0].type).toBe("text");
    const session = sessions.get("test-session");
    expect(session).toBeDefined();
    expect(session?.results.length).toBe(1);
    expect(session?.results[0].status).toBe("fail");
  });

  it("handleGenerateReport generates markdown report", async () => {
    await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
      notes: "Test note",
    });

    const result = await handleGenerateReport({
      sessionId: "test-session",
      format: "markdown",
    });

    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("**Score:** 0%");
    expect(result.content[0].text).toContain("Critical Findings");
  });

  it("handleGetRiskSummary returns summary", async () => {
    const result = await handleGetRiskSummary({ framework: "owasp" });
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.riskBreakdown).toHaveProperty("CRITICAL");
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("handleSearchControls searches across all frameworks", async () => {
    const result = await handleSearchControls({
      query: "injection",
      framework: "all",
    });
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results["OWASP Top 10"]).toBeDefined();
  });

  it("handleCveLookup handles success", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "CVE-2021-44228", description: "Log4j" }),
    } as any);

    const result = await handleCveLookup({ cveId: "CVE-2021-44228" });
    expect(result.content[0].type).toBe("text");
    const data = JSON.parse(result.content[0].text);
    expect(data.id).toBe("CVE-2021-44228");
    expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
  });

  it("handleCveLookup handles error", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
    } as any);

    const result = await handleCveLookup({ cveId: "CVE-UNKNOWN" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });
});
