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
import { FRAMEWORKS } from "./frameworks.js";

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

  it("handleListFrameworks should return list of frameworks", async () => {
    const res = await handleListFrameworks();
    expect(res.content[0].type).toBe("text");
    const data = JSON.parse(res.content[0].text);
    expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
  });

  it("handleGetFramework should return framework data", async () => {
    const res = await handleGetFramework({ framework: "owasp" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
  });

  it("handleGetFramework should return error for invalid framework", async () => {
    const res = await handleGetFramework({ framework: "invalid" });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain("not found");
  });

  it("handleAuditItem should add item to session", async () => {
    const res = await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
      notes: "test note",
    });
    expect(res.isError).toBeUndefined();
    const session = sessions.get("test-session");
    expect(session).toBeDefined();
    expect(session?.results.length).toBe(1);
    expect(session?.results[0].status).toBe("pass");
  });

  it("handleAuditItem should update existing item", async () => {
    await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
    });
    await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });
    const session = sessions.get("test-session");
    expect(session?.results.length).toBe(1);
    expect(session?.results[0].status).toBe("pass");
  });

  it("handleAuditItem should return error for invalid item", async () => {
    const res = await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "INVALID",
      status: "pass",
    });
    expect(res.isError).toBe(true);
  });

  it("handleGenerateReport should return markdown report by default", async () => {
    await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });
    const res = await handleGenerateReport({ sessionId: "test-session" });
    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toContain("# 🔒 Security Audit Report");
    expect(res.content[0].text).toContain("A01");
  });

  it("handleGenerateReport should return json report", async () => {
    await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "pass",
    });
    const res = await handleGenerateReport({ sessionId: "test-session", format: "json" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.session).toBe("test-session");
    expect(data.score).toBe("100%");
  });

  it("handleGenerateReport should return html report", async () => {
    await handleAuditItem({
      sessionId: "test-session",
      framework: "owasp",
      itemId: "A01",
      status: "fail",
    });
    const res = await handleGenerateReport({ sessionId: "test-session", format: "html" });
    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toContain("<!DOCTYPE html>");
  });

  it("handleGenerateReport should return error for invalid session", async () => {
    const res = await handleGenerateReport({ sessionId: "invalid" });
    expect(res.isError).toBe(true);
  });

  it("handleGetRiskSummary should return risk breakdown", async () => {
    const res = await handleGetRiskSummary({ framework: "owasp" });
    expect((res as any).isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it("handleSearchControls should find controls by keyword", async () => {
    const res = await handleSearchControls({ query: "injection", framework: "all" });
    expect((res as any).isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
  });

  it("handleCveLookup should fetch CVE data", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ id: "CVE-2021-44228" }),
    } as any);

    const res = await handleCveLookup({ cveId: "CVE-2021-44228" });
    expect(res.isError).toBeUndefined();
    expect(res.content[0].text).toContain("CVE-2021-44228");
    expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
  });

  it("handleCveLookup should handle API errors", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
    } as any);

    const res = await handleCveLookup({ cveId: "INVALID" });
    expect(res.isError).toBe(true);
  });

  it("handleCveLookup should handle network errors", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network Error"));

    const res = await handleCveLookup({ cveId: "CVE-2021-44228" });
    expect(res.isError).toBe(true);
  });

  it("handleGetFramework should return pci-dss framework data", async () => {
    const res = await handleGetFramework({ framework: "pci-dss" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe("PCI-DSS");
  });

  it("handleGetFramework should return soc2 framework data", async () => {
    const res = await handleGetFramework({ framework: "soc2" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe("SOC 2");
  });

  it("handleGetFramework should return hipaa framework data", async () => {
    const res = await handleGetFramework({ framework: "hipaa" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe("HIPAA Security Rule");
  });

  it("handleGetFramework should return cis-v8 framework data", async () => {
    const res = await handleGetFramework({ framework: "cis-v8" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe("CIS Controls");
  });

  it("handleGetFramework should return gdpr framework data", async () => {
    const res = await handleGetFramework({ framework: "gdpr" });
    expect(res.isError).toBeUndefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe("GDPR");
  });
});
