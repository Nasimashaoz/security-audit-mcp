import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';
import { FRAMEWORKS } from './frameworks.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    }
  };
});

describe('MCP Server Tools', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2023-01-01T00:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

  it('should have all tools registered', () => {
    expect(toolsMap['list_frameworks']).toBeDefined();
    expect(toolsMap['get_framework']).toBeDefined();
    expect(toolsMap['audit_item']).toBeDefined();
    expect(toolsMap['generate_report']).toBeDefined();
    expect(toolsMap['get_risk_summary']).toBeDefined();
    expect(toolsMap['search_controls']).toBeDefined();
    expect(toolsMap['cve_lookup']).toBeDefined();
  });

  it('list_frameworks should return all frameworks', async () => {
    const handler = toolsMap['list_frameworks'].handler;
    const response = await handler({});
    const data = JSON.parse(response.content[0].text);

    expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    expect(data.frameworks.find((f: any) => f.id === 'owasp')).toBeDefined();
    expect(data.frameworks.find((f: any) => f.id === 'gdpr')).toBeDefined();
  });

  it('get_framework should return specific framework details', async () => {
    const handler = toolsMap['get_framework'].handler;
    const response = await handler({ framework: 'owasp' });
    const data = JSON.parse(response.content[0].text);

    expect(data.name).toBe('OWASP Top 10');
    expect(data.items.length).toBe(10);
  });

  it('get_framework should return error for invalid framework', async () => {
    const handler = toolsMap['get_framework'].handler;
    const response = await handler({ framework: 'invalid' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it('audit_item should record an audit result', async () => {
    const handler = toolsMap['audit_item'].handler;
    const response = await handler({
      sessionId: 'test-session-1',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'LGTM'
    });

    const data = JSON.parse(response.content[0].text);
    expect(data.recorded.itemId).toBe('A01');
    expect(data.recorded.status).toBe('pass');
    expect(data.sessionProgress).toBe('1 / 10 items audited');
  });

  it('generate_report should generate a markdown report', async () => {
    const auditHandler = toolsMap['audit_item'].handler;
    await auditHandler({
      sessionId: 'test-session-2',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Needs fix'
    });

    const reportHandler = toolsMap['generate_report'].handler;
    const response = await reportHandler({
      sessionId: 'test-session-2',
      format: 'markdown' // Providing default explicitly for direct handler call
    });

    expect(response.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(response.content[0].text).toContain('OWASP Top 10');
    expect(response.content[0].text).toContain('🚨 Critical Findings');
    expect(response.content[0].text).toContain('A01');
  });

  it('get_risk_summary should return breakdown of risks', async () => {
    const handler = toolsMap['get_risk_summary'].handler;
    const response = await handler({ framework: 'owasp' });
    const data = JSON.parse(response.content[0].text);

    expect(data.riskBreakdown.CRITICAL).toBeDefined();
    expect(data.riskBreakdown.HIGH).toBeDefined();
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it('search_controls should find controls by keyword', async () => {
    const handler = toolsMap['search_controls'].handler;
    const response = await handler({ query: 'access', framework: 'all' });
    const data = JSON.parse(response.content[0].text);

    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results['OWASP Top 10']).toBeDefined();
  });

  it('cve_lookup should fetch CVE details successfully', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: 'CVE-2021-44228', description: 'Log4j vulnerability' })
    } as any);

    const handler = toolsMap['cve_lookup'].handler;
    const response = await handler({ cveId: 'CVE-2021-44228' });
    const data = JSON.parse(response.content[0].text);

    expect(data.id).toBe('CVE-2021-44228');
    expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
  });

  it('cve_lookup should handle 404 correctly', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found'
    } as any);

    const handler = toolsMap['cve_lookup'].handler;
    const response = await handler({ cveId: 'CVE-UNKNOWN' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain('CVE \'CVE-UNKNOWN\' not found');
  });
});
