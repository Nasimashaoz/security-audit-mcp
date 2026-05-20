import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from './index.js';
import { FRAMEWORKS } from './frameworks.js';

// Mock stdio server transport as requested by memory
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => ({
      start: vi.fn(),
      close: vi.fn(),
    })),
  };
});

describe('security-audit-mcp server tools', () => {
  const getToolHandler = (name: string) => {
    const tools = (server as any)._registeredTools;
    return tools[name]?.handler;
  };

  beforeEach(() => {
    global.fetch = vi.fn();
  });

  it('list_frameworks should return all frameworks', async () => {
    const handler = getToolHandler('list_frameworks');
    const result = await handler({});
    const data = JSON.parse(result.content[0].text);
    expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
  });

  it('get_framework should return a specific framework', async () => {
    const handler = getToolHandler('get_framework');
    const result = await handler({ framework: 'owasp' }, { _meta: {} });
    const data = JSON.parse(result.content[0].text);
    expect(data.name).toBe('OWASP Top 10');
  });

  it('get_framework should return error if framework not found', async () => {
    const handler = getToolHandler('get_framework');
    const result = await handler({ framework: 'nonexistent' }, { _meta: {} });
    expect(result.isError).toBe(true);
  });

  it('audit_item should record a result', async () => {
    const handler = getToolHandler('audit_item');
    const result = await handler({ sessionId: 'test1', framework: 'owasp', itemId: 'A01', status: 'pass' }, { _meta: {} });
    const data = JSON.parse(result.content[0].text);
    expect(data.recorded.itemId).toBe('A01');
    expect(data.recorded.status).toBe('pass');
  });

  it('audit_item should return error if item not found', async () => {
    const handler = getToolHandler('audit_item');
    const result = await handler({ sessionId: 'test2', framework: 'owasp', itemId: 'invalid', status: 'pass' }, { _meta: {} });
    expect(result.isError).toBe(true);
  });

  it('generate_report should generate a report in different formats', async () => {
    const auditHandler = getToolHandler('audit_item');
    await auditHandler({ sessionId: 'test3', framework: 'owasp', itemId: 'A01', status: 'pass' }, { _meta: {} });

    const reportHandler = getToolHandler('generate_report');

    // JSON
    const jsonResult = await reportHandler({ sessionId: 'test3', format: 'json' }, { _meta: {} });
    const jsonData = JSON.parse(jsonResult.content[0].text);
    expect(jsonData.score).toBe('100%');

    // Markdown
    const mdResult = await reportHandler({ sessionId: 'test3', format: 'markdown' }, { _meta: {} });
    expect(mdResult.content[0].text).toContain('# 🔒 Security Audit Report');

    // HTML
    const htmlResult = await reportHandler({ sessionId: 'test3', format: 'html' }, { _meta: {} });
    expect(htmlResult.content[0].text).toContain('<!DOCTYPE html>');
  });

  it('generate_report should return error for unknown session', async () => {
    const handler = getToolHandler('generate_report');
    const result = await handler({ sessionId: 'unknown', format: 'json' }, { _meta: {} });
    expect(result.isError).toBe(true);
  });

  it('get_risk_summary should return summary', async () => {
    const handler = getToolHandler('get_risk_summary');
    const result = await handler({ framework: 'owasp' }, { _meta: {} });
    const data = JSON.parse(result.content[0].text);
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
  });

  it('search_controls should find controls by keyword', async () => {
    const handler = getToolHandler('search_controls');
    const result = await handler({ query: 'injection', framework: 'all' }, { _meta: {} });
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);

    const owaspResult = await handler({ query: 'injection', framework: 'owasp' }, { _meta: {} });
    const owaspData = JSON.parse(owaspResult.content[0].text);
    expect(owaspData.totalMatches).toBeGreaterThan(0);
  });

  it('cve_lookup should fetch CVE details', async () => {
    const mockData = { id: 'CVE-2021-44228', description: 'Log4j vulnerability' };
    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockData,
    });

    const handler = getToolHandler('cve_lookup');
    const result = await handler({ cveId: 'CVE-2021-44228' }, { _meta: {} });
    const data = JSON.parse(result.content[0].text);
    expect(data.id).toBe('CVE-2021-44228');
  });

  it('cve_lookup should handle not found', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      status: 404,
    });

    const handler = getToolHandler('cve_lookup');
    const result = await handler({ cveId: 'CVE-9999-9999' }, { _meta: {} });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });

  it('cve_lookup should handle API errors', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      status: 500,
    });

    const handler = getToolHandler('cve_lookup');
    const result = await handler({ cveId: 'CVE-2021-44228' }, { _meta: {} });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('500');
  });

  it('cve_lookup should handle fetch failures', async () => {
    (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

    const handler = getToolHandler('cve_lookup');
    const result = await handler({ cveId: 'CVE-2021-44228' }, { _meta: {} });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Network error');
  });
});
