import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from '../index.js';

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
    return {
        StdioServerTransport: class {
            start() {}
            close() {}
        }
    }
});

describe('security-audit-mcp cve_lookup tool', () => {
  let toolsMap: any;

  beforeEach(() => {
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
    global.fetch = vi.fn();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('cve_lookup tool returns cve data correctly', async () => {
    const mockData = {
      cveMetadata: {
        cveId: "CVE-2021-44228",
        state: "PUBLISHED"
      },
      containers: {
        cna: {
          descriptions: [{ value: "Apache Log4j2 vulnerability" }]
        }
      }
    };

    (global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockData
    });

    const cveLookupTool = toolsMap['cve_lookup'];
    const result = await cveLookupTool.handler({ cveId: 'CVE-2021-44228' });

    expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.cveMetadata.cveId).toBe("CVE-2021-44228");
    expect(parsed.containers.cna.descriptions[0].value).toContain("Apache");
  });

  it('cve_lookup tool handles not found', async () => {
    (global.fetch as any).mockResolvedValue({
      ok: false,
      status: 404
    });

    const cveLookupTool = toolsMap['cve_lookup'];
    const result = await cveLookupTool.handler({ cveId: 'CVE-9999-99999' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe("CVE 'CVE-9999-99999' not found.");
  });

  it('cve_lookup tool handles fetch error', async () => {
    (global.fetch as any).mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error"
    });

    const cveLookupTool = toolsMap['cve_lookup'];
    const result = await cveLookupTool.handler({ cveId: 'CVE-2021-44228' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Failed to fetch CVE data");
  });

  it('cve_lookup tool handles network error', async () => {
    (global.fetch as any).mockRejectedValue(new Error("Network Error"));

    const cveLookupTool = toolsMap['cve_lookup'];
    const result = await cveLookupTool.handler({ cveId: 'CVE-2021-44228' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Error looking up CVE: Network Error");
  });
});
