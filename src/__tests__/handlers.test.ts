import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup,
} from "../handlers.js";
import { sessions } from "../state.js";

describe("Handlers", () => {
  beforeEach(() => {
    sessions.clear();
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2024-01-01T00:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("handleListFrameworks returns a list of frameworks", async () => {
    const result = await handleListFrameworks();
    expect(result.content[0].type).toBe("text");
    expect(JSON.parse(result.content[0].text).frameworks.length).toBeGreaterThan(0);
  });

  it("handleGetFramework returns framework data", async () => {
    const result = await handleGetFramework({ framework: "owasp" });
    expect(result.content[0].type).toBe("text");
    expect(JSON.parse(result.content[0].text).name).toBe("OWASP Top 10");
  });

  it("handleGetFramework returns error for unknown framework", async () => {
    const result = await handleGetFramework({ framework: "unknown" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("handleAuditItem records an audit result", async () => {
    const result = await handleAuditItem({
      sessionId: "session1",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });
    expect(result.content[0].type).toBe("text");
    expect(sessions.get("session1")?.results[0].itemId).toBe("A01");
  });

  it("handleAuditItem returns error for unknown item", async () => {
    const result = await handleAuditItem({
      sessionId: "session1",
      framework: "owasp",
      itemId: "UNKNOWN",
      status: "pass",
    });
    expect(result.isError).toBe(true);
  });

  it("handleGenerateReport generates markdown report", async () => {
    await handleAuditItem({
      sessionId: "session1",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });
    const result = await handleGenerateReport({ sessionId: "session1", format: "markdown" });
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("**Score:** 100%");
  });

  it("handleGenerateReport generates html report", async () => {
    await handleAuditItem({
      sessionId: "session1",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });
    const result = await handleGenerateReport({ sessionId: "session1", format: "html" });
    expect(result.content[0].type).toBe("text");
    expect(result.content[0].text).toContain("<html");
  });

  it("handleGenerateReport generates json report", async () => {
    await handleAuditItem({
      sessionId: "session1",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });
    const result = await handleGenerateReport({ sessionId: "session1", format: "json" });
    expect(result.content[0].type).toBe("text");
    expect(JSON.parse(result.content[0].text).score).toBe("100%");
  });

  it("handleGenerateReport returns error for unknown session", async () => {
    const result = await handleGenerateReport({ sessionId: "unknown", format: "markdown" });
    expect(result.isError).toBe(true);
  });

  it("handleGetRiskSummary returns risk breakdown", async () => {
    const result = await handleGetRiskSummary({ framework: "owasp" });
    expect(result.content[0].type).toBe("text");
    const summary = JSON.parse(result.content[0].text).riskBreakdown;
    expect(summary.CRITICAL.length).toBeGreaterThan(0);
  });

  it("handleSearchControls searches across frameworks", async () => {
    const result = await handleSearchControls({ query: "authentication", framework: "all" });
    expect(result.content[0].type).toBe("text");
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
  });

  it("handleCveLookup fetches CVE data successfully", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ id: "CVE-2021-44228", description: "Log4j" }),
    });
    vi.stubGlobal("fetch", mockFetch);

    const result = await handleCveLookup({ cveId: "CVE-2021-44228" });
    expect(result.content[0].type).toBe("text");
    expect(JSON.parse(result.content[0].text).id).toBe("CVE-2021-44228");
  });

  it("handleCveLookup handles API errors", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
    });
    vi.stubGlobal("fetch", mockFetch);

    const result = await handleCveLookup({ cveId: "CVE-UNKNOWN" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it("handleCveLookup handles network errors", async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error("Network error"));
    vi.stubGlobal("fetch", mockFetch);

    const result = await handleCveLookup({ cveId: "CVE-2021-44228" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Failed to fetch");
  });
});
