import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server, main } from './index.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    }
  };
});

describe('security-audit-mcp server', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2023-01-01T00:00:00Z'));
    global.fetch = vi.fn();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('should run a test', () => {
    expect(true).toBe(true);
  });
});

describe('read-only tools', () => {
  const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

  it('list_frameworks should return available frameworks', async () => {
    const listFrameworks = toolsMap['list_frameworks'];
    const res = await listFrameworks.handler({});
    expect(res.content[0].type).toBe('text');
    const parsed = JSON.parse(res.content[0].text);
    expect(parsed.frameworks).toBeDefined();
    expect(parsed.frameworks.length).toBeGreaterThan(0);
    expect(parsed.frameworks[0].id).toBe('owasp');
  });

  it('get_framework should return specific framework details', async () => {
    const getFramework = toolsMap['get_framework'];
    const res = await getFramework.handler({ framework: 'owasp' });
    expect(res.content[0].type).toBe('text');
    const parsed = JSON.parse(res.content[0].text);
    expect(parsed.name).toBe('OWASP Top 10');
    expect(parsed.items.length).toBe(10);
  });

  it('get_framework should return error for unknown framework', async () => {
    const getFramework = toolsMap['get_framework'];
    const res = await getFramework.handler({ framework: 'unknown' });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('not found');
  });

  it('get_risk_summary should return breakdown of risks', async () => {
    const getRiskSummary = toolsMap['get_risk_summary'];
    const res = await getRiskSummary.handler({ framework: 'owasp' });
    expect(res.content[0].type).toBe('text');
    const parsed = JSON.parse(res.content[0].text);
    expect(parsed.framework).toBe('OWASP Top 10');
    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
  });

  it('search_controls should find controls by keyword', async () => {
    const searchControls = toolsMap['search_controls'];
    const res = await searchControls.handler({ query: 'authentication', framework: 'all' });
    expect(res.content[0].type).toBe('text');
    const parsed = JSON.parse(res.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(parsed.results).toBeDefined();
  });

  it('search_controls should find controls by keyword in specific framework', async () => {
    const searchControls = toolsMap['search_controls'];
    const res = await searchControls.handler({ query: 'broken', framework: 'owasp' });
    expect(res.content[0].type).toBe('text');
    const parsed = JSON.parse(res.content[0].text);
    expect(parsed.results['OWASP Top 10']).toBeDefined();
    expect(parsed.results['OWASP Top 10'][0].title).toContain('Broken');
  });
});

describe('stateful tools', () => {
  const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

  it('audit_item should record a result and generate_report should output JSON', async () => {
    const auditItem = toolsMap['audit_item'];
    const generateReport = toolsMap['generate_report'];

    // Add first result
    const res1 = await auditItem.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Test failure'
    });
    expect(res1.content[0].text).toContain('A01');

    // Add second result (pass)
    await auditItem.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A02',
      status: 'pass'
    });

    // Update first result to check updating logic
    await auditItem.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'Fixed'
    });

    const reportRes = await generateReport.handler({ sessionId: 'test-session', format: 'json' });
    const parsedReport = JSON.parse(reportRes.content[0].text);
    expect(parsedReport.session).toBe('test-session');
    expect(parsedReport.summary.passed).toBe(2);
    expect(parsedReport.score).toBe('100%');
  });

  it('audit_item should return error for unknown item', async () => {
    const auditItem = toolsMap['audit_item'];
    const res = await auditItem.handler({
      sessionId: 'test-session-2',
      framework: 'owasp',
      itemId: 'UNKNOWN',
      status: 'fail'
    });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('not found');
  });

  it('generate_report should handle unknown session', async () => {
    const generateReport = toolsMap['generate_report'];
    const res = await generateReport.handler({ sessionId: 'unknown', format: 'json' });
    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('not found');
  });

  it('generate_report should output markdown', async () => {
    const auditItem = toolsMap['audit_item'];
    const generateReport = toolsMap['generate_report'];

    await auditItem.handler({
      sessionId: 'test-session-md',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Critical issue'
    });

    const reportRes = await generateReport.handler({ sessionId: 'test-session-md', format: 'markdown' });
    expect(reportRes.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(reportRes.content[0].text).toContain('🚨 Critical Findings');
  });

  it('generate_report should output HTML', async () => {
    const auditItem = toolsMap['audit_item'];
    const generateReport = toolsMap['generate_report'];

    await auditItem.handler({
      sessionId: 'test-session-html',
      framework: 'owasp',
      itemId: 'A02',
      status: 'pass'
    });

    const reportRes = await generateReport.handler({ sessionId: 'test-session-html', format: 'html' });
    expect(reportRes.content[0].text).toContain('<!DOCTYPE html>');
    expect(reportRes.content[0].text).toContain('A02');
  });
});

describe('external tools', () => {
  const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

  it('cve_lookup should return CVE details on success', async () => {
    const mockData = { id: 'CVE-2021-44228', description: 'Log4j vulnerability' };
    (global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockData
    });

    const cveLookup = toolsMap['cve_lookup'];
    const res = await cveLookup.handler({ cveId: 'CVE-2021-44228' });

    expect(res.content[0].type).toBe('text');
    expect(JSON.parse(res.content[0].text)).toEqual(mockData);
    expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
  });

  it('cve_lookup should return error on HTTP failure', async () => {
    (global.fetch as any).mockResolvedValue({
      ok: false,
      statusText: 'Not Found'
    });

    const cveLookup = toolsMap['cve_lookup'];
    const res = await cveLookup.handler({ cveId: 'CVE-UNKNOWN' });

    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('Failed to fetch CVE details');
  });

  it('cve_lookup should return error on fetch exception', async () => {
    (global.fetch as any).mockRejectedValue(new Error('Network error'));

    const cveLookup = toolsMap['cve_lookup'];
    const res = await cveLookup.handler({ cveId: 'CVE-2021-44228' });

    expect(res.isError).toBe(true);
    expect(res.content[0].text).toContain('Error looking up CVE');
  });
});
