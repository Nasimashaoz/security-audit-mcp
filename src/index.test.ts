import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
    list_frameworks,
    get_framework,
    audit_item,
    generate_report,
    get_risk_summary,
    search_controls,
    cve_lookup,
    sessions
} from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

// Mock StdioServerTransport as required by memory
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
    return {
        StdioServerTransport: class {
            start() {}
            close() {}
        }
    };
});

describe("Session and Report Tool Handlers", () => {
    beforeEach(() => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date("2024-01-01T12:00:00.000Z"));
        sessions.clear();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it("audit_item should record a result and update session", async () => {
        const sessionId = "test-session";
        const result = await audit_item({
            sessionId,
            framework: "owasp",
            itemId: "A01",
            status: "fail",
            notes: "Test notes"
        });

        expect(result.content[0].type).toBe("text");
        const data = JSON.parse(result.content[0].text);
        expect(data.recorded.itemId).toBe("A01");
        expect(data.recorded.status).toBe("fail");

        const session = sessions.get(sessionId);
        expect(session).toBeDefined();
        expect(session?.results.length).toBe(1);
    });

    it("audit_item should return error for invalid item", async () => {
        const result = await audit_item({
            sessionId: "test-session",
            framework: "owasp",
            itemId: "INVALID",
            status: "fail"
        });
        expect(result.isError).toBe(true);
    });

    it("generate_report should generate a JSON report", async () => {
        const sessionId = "test-session";
        await audit_item({ sessionId, framework: "owasp", itemId: "A01", status: "fail", notes: "Test notes" });
        await audit_item({ sessionId, framework: "owasp", itemId: "A02", status: "pass" });

        const result = await generate_report({ sessionId, format: "json" });
        expect(result.content[0].type).toBe("text");

        const report = JSON.parse(result.content[0].text);
        expect(report.session).toBe(sessionId);
        expect(report.score).toBe("50%");
        expect(report.generatedAt).toBe("2024-01-01T12:00:00.000Z");
    });

    it("generate_report should generate an HTML report", async () => {
        const sessionId = "test-session";
        await audit_item({ sessionId, framework: "owasp", itemId: "A01", status: "fail" });

        const result = await generate_report({ sessionId, format: "html" });
        expect(result.content[0].type).toBe("text");
        expect(result.content[0].text).toContain("<!DOCTYPE html>");
        expect(result.content[0].text).toContain("A01");
    });

    it("generate_report should generate a markdown report", async () => {
        const sessionId = "test-session";
        await audit_item({ sessionId, framework: "owasp", itemId: "A01", status: "fail" });

        const result = await generate_report({ sessionId, format: "markdown" });
        expect(result.content[0].type).toBe("text");
        expect(result.content[0].text).toContain("# 🔒 Security Audit Report");
        expect(result.content[0].text).toContain("| A01 |");
    });

    it("generate_report should handle missing session", async () => {
        const result = await generate_report({ sessionId: "missing", format: "json" });
        expect(result.isError).toBe(true);
    });
});

describe("Basic Tool Handlers", () => {
    it("list_frameworks should return a list of frameworks", async () => {
        const result = await list_frameworks();
        expect(result.content[0].type).toBe("text");
        const data = JSON.parse(result.content[0].text);
        expect(data.frameworks).toBeDefined();
        expect(data.frameworks.length).toBeGreaterThan(0);
        expect(data.frameworks[0].id).toBe("owasp");
    });

    it("get_framework should return a specific framework", async () => {
        const result = await get_framework({ framework: "owasp" });
        expect(result.content[0].type).toBe("text");
        const data = JSON.parse(result.content[0].text);
        expect(data.name).toBe("OWASP Top 10");
        expect(data.items.length).toBeGreaterThan(0);
    });

    it("get_framework should handle not found framework", async () => {
        const result = await get_framework({ framework: "invalid" as any });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("not found");
    });

    it("get_risk_summary should return a summary for a framework", async () => {
        const result = await get_risk_summary({ framework: "owasp" });
        expect(result.content[0].type).toBe("text");
        const data = JSON.parse(result.content[0].text);
        expect(data.framework).toBe("OWASP Top 10");
        expect(data.riskBreakdown.CRITICAL).toBeDefined();
        expect(data.riskBreakdown.HIGH).toBeDefined();
    });

    it("search_controls should find matching controls", async () => {
        const result = await search_controls({ query: "injection", framework: "all" });
        expect(result.content[0].type).toBe("text");
        const data = JSON.parse(result.content[0].text);
        expect(data.totalMatches).toBeGreaterThan(0);
        expect(data.results["OWASP Top 10"]).toBeDefined();
    });

    it("search_controls should handle no matches", async () => {
        const result = await search_controls({ query: "nonexistentstring1234", framework: "all" });
        expect(result.content[0].type).toBe("text");
        const data = JSON.parse(result.content[0].text);
        expect(data.totalMatches).toBe(0);
    });
});

describe("CVE Tool Handlers", () => {
    let fetchSpy: any;

    beforeEach(() => {
        fetchSpy = vi.spyOn(global, "fetch");
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it("cve_lookup should fetch CVE data successfully", async () => {
        const mockResponse = { id: "CVE-2021-44228", description: "Log4j vulnerability" };
        fetchSpy.mockResolvedValueOnce({
            ok: true,
            json: async () => mockResponse
        } as any);

        const result = await cve_lookup({ cveId: "CVE-2021-44228" });
        expect(result.content[0].type).toBe("text");
        const data = JSON.parse(result.content[0].text);
        expect(data.id).toBe("CVE-2021-44228");
        expect(fetchSpy).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
    });

    it("cve_lookup should handle fetch errors (e.g. not found)", async () => {
        fetchSpy.mockResolvedValueOnce({
            ok: false,
            statusText: "Not Found"
        } as any);

        const result = await cve_lookup({ cveId: "INVALID-CVE" });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Failed to fetch CVE data: Not Found");
    });

    it("cve_lookup should handle network exceptions", async () => {
        fetchSpy.mockRejectedValueOnce(new Error("Network Error"));

        const result = await cve_lookup({ cveId: "CVE-123" });
        expect(result.isError).toBe(true);
        expect(result.content[0].text).toContain("Error fetching CVE data: Network Error");
    });
});
