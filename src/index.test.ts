import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

// Mock the global fetch for CVE lookups
global.fetch = vi.fn();

describe('MCP Server', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const getToolHandler = (toolName: string) => {
    const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
    return toolsMap[toolName]?.handler;
  };

  it('should list frameworks correctly', async () => {
    const handler = getToolHandler('list_frameworks');
    expect(handler).toBeDefined();

    const result = await handler({});
    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.frameworks).toBeDefined();
    expect(parsed.frameworks.some((fw: any) => fw.id === 'owasp')).toBe(true);
    expect(parsed.frameworks.some((fw: any) => fw.id === 'pcidss')).toBe(true);
  });

  it('should get a specific framework', async () => {
    const handler = getToolHandler('get_framework');
    expect(handler).toBeDefined();

    const result = await handler({ framework: 'owasp' });
    expect(result.content[0].type).toBe('text');

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.name).toBe('OWASP Top 10');
  });

  it('should handle get_framework error for missing framework', async () => {
    const handler = getToolHandler('get_framework');

    // While Zod usually catches this before the handler, testing the fallback
    const result = await handler({ framework: 'nonexistent' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });

  it('should search controls correctly', async () => {
    const handler = getToolHandler('search_controls');

    const result = await handler({ query: 'authentication', framework: 'all' });
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(parsed.query).toBe('authentication');
  });

  it('should audit an item correctly', async () => {
    const handler = getToolHandler('audit_item');

    const result = await handler({
      sessionId: 'test-session-1',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'Looks good'
    });

    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.recorded.status).toBe('pass');
    expect(parsed.recorded.notes).toBe('Looks good');
  });

  it('should handle audit_item error for missing item', async () => {
    const handler = getToolHandler('audit_item');

    const result = await handler({
      sessionId: 'test-session-2',
      framework: 'owasp',
      itemId: 'NONEXISTENT',
      status: 'pass'
    });

    expect(result.isError).toBe(true);
  });

  it('should get risk summary', async () => {
    const handler = getToolHandler('get_risk_summary');

    const result = await handler({ framework: 'owasp' });
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.riskBreakdown).toBeDefined();
    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
  });

  it('should generate report in markdown', async () => {
    // First record an item
    const auditHandler = getToolHandler('audit_item');
    await auditHandler({
      sessionId: 'report-session-1',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Failed test'
    });

    const reportHandler = getToolHandler('generate_report');
    const result = await reportHandler({
      sessionId: 'report-session-1',
      format: 'markdown'
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(result.content[0].text).toContain('Failed test');
  });

  it('should return error for generate_report with missing session', async () => {
    const handler = getToolHandler('generate_report');

    const result = await handler({
      sessionId: 'missing-session',
      format: 'markdown'
    });

    expect(result.isError).toBe(true);
  });

  describe('cve_lookup', () => {
    it('should lookup a CVE successfully', async () => {
      const mockData = { id: 'CVE-2021-44228', description: 'Log4j vulnerability' };
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockData
      });

      const handler = getToolHandler('cve_lookup');
      const result = await handler({ cveId: 'CVE-2021-44228' });

      expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
      expect(result.content[0].type).toBe('text');
      expect(JSON.parse(result.content[0].text)).toEqual(mockData);
    });

    it('should handle CVE not found (404)', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      const handler = getToolHandler('cve_lookup');
      const result = await handler({ cveId: 'CVE-UNKNOWN' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });

    it('should handle API errors', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500
      });

      const handler = getToolHandler('cve_lookup');
      const result = await handler({ cveId: 'CVE-2021-44228' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('API error: 500');
    });

    it('should handle network/fetch errors', async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

      const handler = getToolHandler('cve_lookup');
      const result = await handler({ cveId: 'CVE-2021-44228' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Error looking up CVE: Network error');
    });
  });
});
