import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { server } from "./index.js";
import { FRAMEWORKS } from "./frameworks.js";

const tools = (server as any)._registeredTools;

describe("MCP Tools", () => {
  describe("list_frameworks", () => {
    it("should list all available frameworks", async () => {
      const handler = tools["list_frameworks"].handler;
      const result = await handler({});

      expect(result.content).toHaveLength(1);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(parsed.frameworks[0].id).toBe("owasp");
    });
  });

  describe("get_framework", () => {
    it("should return the full framework", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "owasp" });

      expect(result.content).toHaveLength(1);
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe("OWASP Top 10");
      expect(parsed.items.length).toBeGreaterThan(0);
    });

    it("should return an error for non-existent framework", async () => {
      const handler = tools["get_framework"].handler;
      const result = await handler({ framework: "invalid_framework" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe("cve_lookup", () => {
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
      originalFetch = global.fetch;
    });

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it("should return CVE details on success", async () => {
      const mockData = { id: "CVE-1234-5678", description: "Test vulnerability" };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockData)
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "CVE-1234-5678" });

      expect(result.content).toHaveLength(1);
      expect(JSON.parse(result.content[0].text)).toEqual(mockData);
      expect(global.fetch).toHaveBeenCalledWith("https://cveawg.mitre.org/api/cve/CVE-1234-5678");
    });

    it("should return error on failed fetch", async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        statusText: "Not Found"
      });

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "INVALID" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error fetching CVE details: Not Found");
    });

    it("should return error on exception", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network failure"));

      const handler = tools["cve_lookup"].handler;
      const result = await handler({ cveId: "ANY" });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch CVE: Network failure");
    });
  });
});
