import { describe, it, expect, vi, beforeEach } from "vitest";
import { server } from "./index.js";

// Ensure global fetch is mocked
global.fetch = vi.fn();

describe("security-audit-mcp server tools", () => {
  let toolsMap: any;

  beforeEach(() => {
    // Safely access the internal tools map
    toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools || {};
    vi.clearAllMocks();
  });

  it("should list frameworks correctly", async () => {
    const handler = toolsMap["list_frameworks"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.some((f: any) => f.id === "owasp")).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === "pcidss")).toBe(true);
  });

  it("should get a specific framework", async () => {
    const handler = toolsMap["get_framework"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({ framework: "owasp" }, {});
    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe("OWASP Top 10");
  });

  it("should handle get_framework for invalid framework", async () => {
    const handler = toolsMap["get_framework"]?.handler;
    expect(handler).toBeDefined();

    // Although zod will catch this in real usage, we simulate direct handler call
    const response = await handler({ framework: "invalid" }, {});
    expect(response.isError).toBe(true);
  });

  it("should look up a CVE", async () => {
    const handler = toolsMap["cve_lookup"]?.handler;
    expect(handler).toBeDefined();

    const mockCveData = { cveMetadata: { cveId: "CVE-2021-44228" } };
    (global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockCveData,
    });

    const response = await handler({ cveId: "CVE-2021-44228" }, {});
    expect(response.content[0].type).toBe("text");
    const data = JSON.parse(response.content[0].text);
    expect(data.cveMetadata.cveId).toBe("CVE-2021-44228");
    expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-2021-44228");
  });

  it("should handle CVE lookup failure (404)", async () => {
    const handler = toolsMap["cve_lookup"]?.handler;
    expect(handler).toBeDefined();

    (global.fetch as any).mockResolvedValue({
      ok: false,
      status: 404,
    });

    const response = await handler({ cveId: "CVE-UNKNOWN" }, {});
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it("should search controls", async () => {
    const handler = toolsMap["search_controls"]?.handler;
    expect(handler).toBeDefined();

    const response = await handler({ query: "injection", framework: "all" }, {});
    const data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
  });
});
