import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

const { StdioServerTransport } = vi.hoisted(() => ({
  StdioServerTransport: class {
    start() {}
    close() {}
  }
}));

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport
}));

describe('Security Audit MCP Server', () => {
  let toolsMap: any;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    global.fetch = vi.fn();
    const toolRegistry = (server as any)._registeredTools || (server as any)._tools || (server as any).registeredTools;
    toolsMap = Object.fromEntries(
      Object.entries(toolRegistry).map(([k, v]: [string, any]) => [k, async (args: any) => {
        return await v.handler(args);
      }])
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('list_frameworks', () => {
    it('returns a list of available frameworks', async () => {
      const handler = toolsMap['list_frameworks'];
      const result = await handler({});
      expect(result.content[0].type).toBe('text');
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks).toBeDefined();
      expect(parsed.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
      expect(parsed.frameworks.some((f: any) => f.id === 'pcidss')).toBe(true);
    });
  });

  describe('get_framework', () => {
    it('returns framework details if valid', async () => {
      const handler = toolsMap['get_framework'];
      const result = await handler({ framework: 'owasp' });
      expect(result.content[0].type).toBe('text');
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe('OWASP Top 10');
      expect(parsed.items.length).toBeGreaterThan(0);
    });

    it('returns error if framework not found', async () => {
      const handler = toolsMap['get_framework'];
      const result = await handler({ framework: 'invalid_fw' });
      expect(result.isError).toBe(true);
    });
  });

  describe('audit_item', () => {
    it('records audit result correctly', async () => {
      const handler = toolsMap['audit_item'];
      const sessionId = 'test-session-1';

      const result = await handler({
        sessionId,
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Failed to implement proper access controls'
      });

      expect(result.content[0].type).toBe('text');
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.itemId).toBe('A01');
      expect(parsed.recorded.status).toBe('fail');
      expect(parsed.sessionProgress).toContain('1 /');
    });

    it('returns error if item not found', async () => {
      const handler = toolsMap['audit_item'];
      const result = await handler({
        sessionId: 'test-session-1',
        framework: 'owasp',
        itemId: 'INVALID_ITEM',
        status: 'pass'
      });
      expect(result.isError).toBe(true);
    });
  });

  describe('generate_report', () => {
    beforeEach(async () => {
      const auditHandler = toolsMap['audit_item'];
      await auditHandler({
        sessionId: 'report-session',
        framework: 'nist',
        itemId: 'AC-1',
        status: 'pass',
      });
      await auditHandler({
        sessionId: 'report-session',
        framework: 'nist',
        itemId: 'AC-2',
        status: 'fail',
        notes: 'Not disabled'
      });
    });

    it('returns error if session not found', async () => {
      const handler = toolsMap['generate_report'];
      const result = await handler({ sessionId: 'invalid-session', format: 'json' });
      expect(result.isError).toBe(true);
    });

    it('generates json report correctly', async () => {
      const handler = toolsMap['generate_report'];
      const result = await handler({ sessionId: 'report-session', format: 'json' });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.summary.passed).toBe(1);
      expect(parsed.summary.failed).toBe(1);
      expect(parsed.score).toBe('50%');
      expect(parsed.generatedAt).toBe('2024-01-01T00:00:00.000Z');
    });

    it('generates markdown report correctly', async () => {
      const handler = toolsMap['generate_report'];
      const result = await handler({ sessionId: 'report-session', format: 'markdown' });
      expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(result.content[0].text).toContain('**Score:** 50%');
    });

    it('generates html report correctly', async () => {
      const handler = toolsMap['generate_report'];
      const result = await handler({ sessionId: 'report-session', format: 'html' });
      expect(result.content[0].text).toContain('<!DOCTYPE html>');
      expect(result.content[0].text).toContain('50%</div>');
    });
  });

  describe('get_risk_summary', () => {
    it('returns risk summary for framework', async () => {
      const handler = toolsMap['get_risk_summary'];
      const result = await handler({ framework: 'iso27001' });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(parsed.riskBreakdown.HIGH.length).toBeGreaterThan(0);
    });
  });

  describe('search_controls', () => {
    it('searches controls across all frameworks', async () => {
      const handler = toolsMap['search_controls'];
      const result = await handler({ query: 'encrypt', framework: 'all' });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
    });

    it('searches controls within a specific framework', async () => {
      const handler = toolsMap['search_controls'];
      const result = await handler({ query: 'encrypt', framework: 'owasp' });
      const parsed = JSON.parse(result.content[0].text);
      expect(Object.keys(parsed.results).length).toBe(1);
      expect(parsed.results['OWASP Top 10']).toBeDefined();
    });
  });

  describe('cve_lookup', () => {
    it('handles successful API response', async () => {
      const mockCveData = { id: 'CVE-2021-34527', description: 'Test CVE' };
      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockCveData
      });

      const handler = toolsMap['cve_lookup'];
      const result = await handler({ cveId: 'CVE-2021-34527' });

      expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-34527');
      expect(result.content[0].type).toBe('text');
      expect(JSON.parse(result.content[0].text)).toEqual(mockCveData);
    });

    it('handles API error response', async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 404
      });

      const handler = toolsMap['cve_lookup'];
      const result = await handler({ cveId: 'CVE-INVALID' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Failed to fetch CVE-INVALID: HTTP 404');
    });

    it('handles network error', async () => {
      (global.fetch as any).mockRejectedValue(new Error('Network error'));

      const handler = toolsMap['cve_lookup'];
      const result = await handler({ cveId: 'CVE-2021-34527' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Error fetching CVE-2021-34527: Network error');
    });
  });
});
