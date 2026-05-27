import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { FRAMEWORKS } from '../frameworks.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: class {
    async start() {}
    async close() {}
  },
}));

describe('MCP Server', () => {
  let server: any;
  beforeEach(async () => {
    // Dynamically import to ensure fresh state if needed, or just import once
    const module = await import('../index.js');
    server = (module as any).server;
  });

  afterEach(() => {
    vi.resetModules();
  });

  it('should register all expected tools', () => {
    expect(server).toBeDefined();
    // Safely fallback to getting registered tools depending on SDK internal structure
    const toolsMap = (server as any)._registeredTools || (server as any)._tools;
    const tools = toolsMap instanceof Map ? Object.fromEntries(toolsMap) : toolsMap;

    expect(tools).toBeDefined();
    const toolNames = Object.keys(tools);
    expect(toolNames).toContain('list_frameworks');
    expect(toolNames).toContain('get_framework');
    expect(toolNames).toContain('audit_item');
    expect(toolNames).toContain('generate_report');
    expect(toolNames).toContain('get_risk_summary');
    expect(toolNames).toContain('search_controls');
    expect(toolNames).toContain('cve_lookup');
  });

  describe('cve_lookup tool', () => {
    let originalFetch: any;

    beforeEach(() => {
      originalFetch = global.fetch;
    });

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it('should successfully lookup a CVE', async () => {
      const mockResponse = {
        cveMetadata: {
          cveId: 'CVE-2021-44228',
          state: 'PUBLISHED',
          datePublished: '2021-12-10T10:00:00.000Z',
          dateUpdated: '2021-12-11T10:00:00.000Z'
        },
        containers: {
          cna: {
            title: 'Log4j vulnerability',
            descriptions: [{ value: 'A really bad bug' }],
            affected: [{ vendor: 'Apache', product: 'Log4j' }]
          }
        }
      };

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const toolsMap = (server as any)._registeredTools || (server as any)._tools;
      const tools = toolsMap instanceof Map ? Object.fromEntries(toolsMap) : toolsMap;
      const cveLookup = tools['cve_lookup'];

      const result = await cveLookup.handler({ cveId: 'CVE-2021-44228' });
      expect(result.isError).toBeFalsy();
      expect(result.content[0].text).toContain('CVE-2021-44228');
      expect(result.content[0].text).toContain('Log4j vulnerability');
    });

    it('should handle missing CVE', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      });

      const toolsMap = (server as any)._registeredTools || (server as any)._tools;
      const tools = toolsMap instanceof Map ? Object.fromEntries(toolsMap) : toolsMap;
      const cveLookup = tools['cve_lookup'];

      const result = await cveLookup.handler({ cveId: 'CVE-UNKNOWN' });
      expect(result.isError).toBeTruthy();
      expect(result.content[0].text).toContain('not found');
    });

    it('should handle fetch errors', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

      const toolsMap = (server as any)._registeredTools || (server as any)._tools;
      const tools = toolsMap instanceof Map ? Object.fromEntries(toolsMap) : toolsMap;
      const cveLookup = tools['cve_lookup'];

      const result = await cveLookup.handler({ cveId: 'CVE-2021-44228' });
      expect(result.isError).toBeTruthy();
      expect(result.content[0].text).toContain('Network error');
    });
  });
});
