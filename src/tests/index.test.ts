import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server, sessions } from '../index.js';
import { FRAMEWORKS } from '../frameworks.js';

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
    return {
        StdioServerTransport: class {
            start() {}
            close() {}
        }
    }
});

describe('security-audit-mcp server framework tools', () => {
  let toolsMap: any;

  beforeEach(() => {
    sessions.clear();
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2023-01-01T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('list_frameworks tool returns all frameworks', async () => {
    const listFrameworksTool = toolsMap['list_frameworks'];
    const result = await listFrameworksTool.handler({});

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.frameworks).toHaveLength(Object.keys(FRAMEWORKS).length);
    expect(parsed.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
    expect(parsed.frameworks.some((f: any) => f.id === 'pcidss')).toBe(true);
  });

  it('get_framework tool returns framework checklist', async () => {
    const getFrameworkTool = toolsMap['get_framework'];

    const result = await getFrameworkTool.handler({ framework: 'owasp' });
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.name).toBe('OWASP Top 10');
    expect(parsed.items).toHaveLength(10);
  });

  it('get_framework tool handles not found', async () => {
    const getFrameworkTool = toolsMap['get_framework'];

    const result = await getFrameworkTool.handler({ framework: 'unknown' });
    expect(result.isError).toBe(true);
  });

  it('audit_item records results properly', async () => {
    const auditItemTool = toolsMap['audit_item'];

    const result = await auditItemTool.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'All good'
    });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.recorded.itemId).toBe('A01');
    expect(parsed.recorded.status).toBe('pass');
    expect(parsed.recorded.notes).toBe('All good');

    const session = sessions.get('test-session');
    expect(session).toBeDefined();
    expect(session?.results).toHaveLength(1);
    expect(session?.results[0].itemId).toBe('A01');

    // Update existing result to cover the update branch
    const updateResult = await auditItemTool.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Updated'
    });

    const updatedParsed = JSON.parse(updateResult.content[0].text);
    expect(updatedParsed.recorded.status).toBe('fail');
    expect(session?.results).toHaveLength(1);
  });

  it('audit_item handles item not found', async () => {
    const auditItemTool = toolsMap['audit_item'];

    const result = await auditItemTool.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'unknown-item',
      status: 'pass'
    });

    expect(result.isError).toBe(true);
  });

  it('generate_report creates JSON report correctly', async () => {
    sessions.set('test-session', {
      id: 'test-session',
      framework: 'owasp',
      results: [
        { itemId: 'A01', title: 'Broken Access Control', risk: 'CRITICAL', status: 'pass', notes: '' },
        { itemId: 'A02', title: 'Cryptographic Failures', risk: 'CRITICAL', status: 'fail', notes: 'Fix encryption' }
      ],
      startedAt: new Date().toISOString()
    });

    const generateReportTool = toolsMap['generate_report'];
    const result = await generateReportTool.handler({
      sessionId: 'test-session',
      format: 'json'
    });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.score).toBe('50%');
    expect(parsed.summary.passed).toBe(1);
    expect(parsed.summary.failed).toBe(1);
    expect(parsed.criticalFindings).toHaveLength(1);
  });

  it('generate_report creates markdown report correctly', async () => {
    sessions.set('test-session', {
      id: 'test-session',
      framework: 'owasp',
      results: [
        { itemId: 'A01', title: 'Broken Access Control', risk: 'CRITICAL', status: 'fail', notes: 'Urgent' }
      ],
      startedAt: new Date().toISOString()
    });

    const generateReportTool = toolsMap['generate_report'];
    const result = await generateReportTool.handler({
      sessionId: 'test-session',
      format: 'markdown'
    });

    expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(result.content[0].text).toContain('## 🚨 Critical Findings');
    expect(result.content[0].text).toContain('A01');
  });

  it('generate_report creates HTML report correctly', async () => {
    sessions.set('test-session', {
      id: 'test-session',
      framework: 'owasp',
      results: [
        { itemId: 'A01', title: 'Broken Access Control', risk: 'CRITICAL', status: 'fail', notes: 'Urgent' }
      ],
      startedAt: new Date().toISOString()
    });

    const generateReportTool = toolsMap['generate_report'];
    const result = await generateReportTool.handler({
      sessionId: 'test-session',
      format: 'html'
    });

    expect(result.content[0].text).toContain('<!DOCTYPE html>');
    expect(result.content[0].text).toContain('A01');
  });

  it('generate_report handles session not found', async () => {
    const generateReportTool = toolsMap['generate_report'];
    const result = await generateReportTool.handler({
      sessionId: 'unknown-session',
      format: 'json'
    });

    expect(result.isError).toBe(true);
  });

  it('get_risk_summary returns risk breakdown', async () => {
    const getRiskSummaryTool = toolsMap['get_risk_summary'];
    const result = await getRiskSummaryTool.handler({ framework: 'owasp' });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.framework).toBe('OWASP Top 10');
    expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(parsed.riskBreakdown.HIGH.length).toBeGreaterThan(0);
  });

  it('search_controls searches all frameworks by keyword', async () => {
    const searchControlsTool = toolsMap['search_controls'];
    const result = await searchControlsTool.handler({ query: 'encryption', framework: 'all' });

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(parsed.results['PCI-DSS']).toBeDefined();
    expect(parsed.results['GDPR']).toBeDefined();
  });
});
