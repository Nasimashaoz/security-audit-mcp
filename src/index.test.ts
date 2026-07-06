import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn().mockImplementation(() => ({
    start: vi.fn(),
    close: vi.fn()
  }))
}));

describe('MCP Server Tools', () => {
  let toolsMap: Record<string, any>;

  beforeEach(() => {
    // Access the internal tools registry dynamically to avoid type errors
    toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    if (!toolsMap) {
      throw new Error("Could not find the internal tools map on the server instance.");
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('list_frameworks', () => {
    it('should list all available frameworks including the new ones', async () => {
      const handler = toolsMap['list_frameworks'].handler;
      const result = await handler({});
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
      expect(data.frameworks.some((f: any) => f.id === 'pci-dss')).toBe(true);
    });
  });

  describe('get_framework', () => {
    it('should return the full checklist for a valid framework', async () => {
      const handler = toolsMap['get_framework'].handler;
      const result = await handler({ framework: 'owasp' });
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe('text');
      const fw = JSON.parse(result.content[0].text);
      expect(fw.name).toBe('OWASP Top 10');
      expect(fw.items).toBeDefined();
      expect(fw.items.length).toBeGreaterThan(0);
    });

    it('should return an error for an invalid framework (bypassing zod for this test)', async () => {
      const handler = toolsMap['get_framework'].handler;
      const result = await handler({ framework: 'invalid_framework' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe('audit_item', () => {
    it('should record an audit item successfully', async () => {
      const handler = toolsMap['audit_item'].handler;
      const sessionId = 'test-session-1';
      const result = await handler({
        sessionId,
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass',
        notes: 'looks good'
      });
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('pass');
    });

    it('should return error if item is not found', async () => {
      const handler = toolsMap['audit_item'].handler;
      const result = await handler({
        sessionId: 'test-session-2',
        framework: 'owasp',
        itemId: 'INVALID_ITEM',
        status: 'pass'
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe('generate_report', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should generate a json report for an existing session', async () => {
      const auditHandler = toolsMap['audit_item'].handler;
      const sessionId = 'report-session-1';
      await auditHandler({
        sessionId,
        framework: 'nist',
        itemId: 'AC-1',
        status: 'fail',
        notes: 'missing policy'
      });

      const reportHandler = toolsMap['generate_report'].handler;
      const result = await reportHandler({
        sessionId,
        format: 'json'
      });

      expect(result.content).toBeDefined();
      const report = JSON.parse(result.content[0].text);
      expect(report.session).toBe(sessionId);
      expect(report.score).toBe('0%');
      expect(report.summary.failed).toBe(1);
    });

    it('should return error for non-existent session', async () => {
      const reportHandler = toolsMap['generate_report'].handler;
      const result = await reportHandler({
        sessionId: 'invalid-session',
        format: 'markdown'
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });
  });

  describe('get_risk_summary', () => {
    it('should return a breakdown of risks', async () => {
      const handler = toolsMap['get_risk_summary'].handler;
      const result = await handler({ framework: 'iso27001' });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(Array.isArray(data.riskBreakdown.CRITICAL)).toBe(true);
    });
  });

  describe('search_controls', () => {
    it('should return matched controls', async () => {
      const handler = toolsMap['search_controls'].handler;
      const result = await handler({ query: 'encryption', framework: 'all' });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.query).toBe('encryption');
      expect(data.totalMatches).toBeGreaterThan(0);
    });
  });

  describe('cve_lookup', () => {
    it('should successfully fetch CVE details', async () => {
      const mockResponse = { id: 'CVE-2021-44228', details: 'log4shell' };
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse)
      } as Response);

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-2021-44228' });
      expect(result.content).toBeDefined();
      expect(result.content[0].text).toContain('CVE-2021-44228');
    });

    it('should handle 404 error correctly', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      } as Response);

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-INVALID' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });

    it('should handle general fetch errors', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-1234' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Error looking up CVE');
    });
  });
});
