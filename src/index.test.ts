import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from './index.js';
import { FRAMEWORKS } from './frameworks.js';

describe('security-audit-mcp tools - Frameworks & Enums', () => {
  const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;

  it('should list all frameworks via list_frameworks', async () => {
    const listFrameworks = toolsMap['list_frameworks'];
    const result = await listFrameworks.handler({});

    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    expect(parsed.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
    expect(parsed.frameworks.some((f: any) => f.id === 'pcidss')).toBe(true);
  });

  it('should return a specific framework via get_framework', async () => {
    const getFramework = toolsMap['get_framework'];
    const result = await getFramework.handler({ framework: 'owasp' });

    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.name).toBe('OWASP Top 10');
    expect(parsed.items.length).toBe(10);
  });

  it('should return an error for invalid framework in get_framework', async () => {
    const getFramework = toolsMap['get_framework'];
    const result = await getFramework.handler({ framework: 'invalid' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });

  it('should search controls across all frameworks via search_controls', async () => {
    const searchControls = toolsMap['search_controls'];
    const result = await searchControls.handler({ query: 'authentication', framework: 'all' });

    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.query).toBe('authentication');
    expect(parsed.totalMatches).toBeGreaterThan(0);
    // Should have results from at least OWASP
    expect(parsed.results['OWASP Top 10']).toBeDefined();
  });
});

describe('security-audit-mcp tools - Audit Capabilities', () => {
  const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
  const sessionId = 'test-session-1';

  it('should get risk summary by severity via get_risk_summary', async () => {
    const getRiskSummary = toolsMap['get_risk_summary'];
    const result = await getRiskSummary.handler({ framework: 'owasp' });

    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.framework).toBe('OWASP Top 10');
    expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(parsed.riskBreakdown.HIGH.length).toBeGreaterThan(0);
  });

  it('should record an audit result via audit_item', async () => {
    const auditItem = toolsMap['audit_item'];
    const result = await auditItem.handler({
      sessionId,
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'Checked and passed'
    });

    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.recorded.itemId).toBe('A01');
    expect(parsed.recorded.status).toBe('pass');
    expect(parsed.sessionProgress).toContain('items audited');
  });

  it('should update an existing audit result via audit_item', async () => {
    const auditItem = toolsMap['audit_item'];
    // Initial fail
    await auditItem.handler({ sessionId, framework: 'owasp', itemId: 'A02', status: 'fail' });

    // Update to pass
    const result = await auditItem.handler({ sessionId, framework: 'owasp', itemId: 'A02', status: 'pass' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.recorded.status).toBe('pass');
  });

  it('should error for invalid item in audit_item', async () => {
    const auditItem = toolsMap['audit_item'];
    const result = await auditItem.handler({
      sessionId,
      framework: 'owasp',
      itemId: 'INVALID_ID',
      status: 'pass'
    });

    expect(result.isError).toBe(true);
  });

  it('should generate JSON report via generate_report', async () => {
    const generateReport = toolsMap['generate_report'];
    const result = await generateReport.handler({ sessionId, format: 'json' });

    expect(result.isError).toBeUndefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.session).toBe(sessionId);
    expect(parsed.framework).toBe('OWASP Top 10');
    expect(parsed.summary.passed).toBe(2); // A01 and A02
    expect(parsed.summary.failed).toBe(0);
  });

  it('should generate Markdown report via generate_report', async () => {
    const generateReport = toolsMap['generate_report'];
    const result = await generateReport.handler({ sessionId, format: 'markdown' });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(result.content[0].text).toContain('| A01 |');
  });

  it('should generate HTML report via generate_report', async () => {
    const generateReport = toolsMap['generate_report'];
    const result = await generateReport.handler({ sessionId, format: 'html' });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].text).toContain('<!DOCTYPE html>');
    expect(result.content[0].text).toContain('<td>A01</td>');
  });

  it('should error for invalid session in generate_report', async () => {
    const generateReport = toolsMap['generate_report'];
    const result = await generateReport.handler({ sessionId: 'invalid-session-id', format: 'json' });

    expect(result.isError).toBe(true);
  });
});

describe('security-audit-mcp tools - cve_lookup', () => {
  const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;

  // Save original fetch to restore later
  const originalFetch = global.fetch;

  beforeEach(() => {
    global.fetch = vi.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('should return CVE data on successful fetch', async () => {
    const cveLookup = toolsMap['cve_lookup'];
    const mockData = { cveId: 'CVE-2021-44228', description: 'Log4Shell' };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockData
    });

    const result = await cveLookup.handler({ cveId: 'CVE-2021-44228' });

    expect(result.isError).toBeUndefined();
    expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toEqual(mockData);
  });

  it('should return error if CVE is not found (404)', async () => {
    const cveLookup = toolsMap['cve_lookup'];

    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      status: 404
    });

    const result = await cveLookup.handler({ cveId: 'CVE-UNKNOWN' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found in MITRE database');
  });

  it('should return generic error for other HTTP errors', async () => {
    const cveLookup = toolsMap['cve_lookup'];

    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      status: 500
    });

    const result = await cveLookup.handler({ cveId: 'CVE-123' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('HTTP error 500');
  });

  it('should catch and return error on fetch failure', async () => {
    const cveLookup = toolsMap['cve_lookup'];

    (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

    const result = await cveLookup.handler({ cveId: 'CVE-123' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Network error');
  });
});

describe('security-audit-mcp tools - Edge Cases', () => {
  const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;

  it('should generate markdown report cleanly if no critical findings exist', async () => {
    const generateReport = toolsMap['generate_report'];
    const auditItem = toolsMap['audit_item'];

    const sid = 'no-crit-session';
    await auditItem.handler({ sessionId: sid, framework: 'owasp', itemId: 'A08', status: 'pass' }); // MEDIUM risk

    const result = await generateReport.handler({ sessionId: sid, format: 'markdown' });
    expect(result.content[0].text).not.toContain('## 🚨 Critical Findings');
  });
});

describe('security-audit-mcp tools - Critical findings markdown', () => {
  const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;

  it('should generate markdown report with critical findings and notes', async () => {
    const generateReport = toolsMap['generate_report'];
    const auditItem = toolsMap['audit_item'];

    const sid = 'crit-session';
    await auditItem.handler({ sessionId: sid, framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'Fix immediately' });
    await auditItem.handler({ sessionId: sid, framework: 'owasp', itemId: 'A02', status: 'fail' }); // No notes

    const result = await generateReport.handler({ sessionId: sid, format: 'markdown' });
    expect(result.content[0].text).toContain('## 🚨 Critical Findings');
    expect(result.content[0].text).toContain('Fix immediately');
  });
});
