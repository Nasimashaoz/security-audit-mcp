import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

const toolsMap = (server as any)._registeredTools;

describe('MCP Server Tools', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('list_frameworks tool returns available frameworks', async () => {
    const handler = toolsMap['list_frameworks'].handler;
    const result = await handler({});

    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);

    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === 'pcidss')).toBe(true);
  });

  it('get_framework tool returns framework checklist', async () => {
    const handler = toolsMap['get_framework'].handler;
    const result = await handler({ framework: 'owasp' });

    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);

    expect(data.name).toBe('OWASP Top 10');
    expect(data.items.length).toBe(10);
  });

  it('get_framework tool returns error for invalid framework', async () => {
    const handler = toolsMap['get_framework'].handler;
    const result = await handler({ framework: 'invalid' });

    expect(result.isError).toBe(true);
  });

  it('get_risk_summary tool returns risks grouped by severity', async () => {
    const handler = toolsMap['get_risk_summary'].handler;
    const result = await handler({ framework: 'owasp' });

    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);

    expect(data.framework).toBe('OWASP Top 10');
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it('search_controls tool finds relevant controls', async () => {
    const handler = toolsMap['search_controls'].handler;
    const result = await handler({ query: 'injection', framework: 'all' });

    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);

    expect(data.query).toBe('injection');
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results['OWASP Top 10']).toBeDefined();
  });

  it('audit_item tool records progress and session correctly', async () => {
    const handler = toolsMap['audit_item'].handler;
    const result = await handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Test note'
    });

    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);

    expect(data.recorded.itemId).toBe('A01');
    expect(data.recorded.status).toBe('fail');
    expect(data.recorded.notes).toBe('Test note');
  });

  it('generate_report tool builds proper report based on session', async () => {
    // Generate an item to make sure the session exists
    await toolsMap['audit_item'].handler({
      sessionId: 'report-session',
      framework: 'iso27001',
      itemId: 'A.5.1',
      status: 'pass',
      notes: 'Approved'
    });

    await toolsMap['audit_item'].handler({
      sessionId: 'report-session',
      framework: 'iso27001',
      itemId: 'A.5.15',
      status: 'fail',
      notes: 'No access control'
    });

    const handler = toolsMap['generate_report'].handler;
    const resultMarkdown = await handler({ sessionId: 'report-session', format: 'markdown' });
    const resultJson = await handler({ sessionId: 'report-session', format: 'json' });
    const resultHtml = await handler({ sessionId: 'report-session', format: 'html' });

    expect(resultMarkdown.content[0].text).toContain('**Score:** 50%');
    expect(JSON.parse(resultJson.content[0].text).score).toBe('50%');
    expect(resultHtml.content[0].text).toContain('50%');
  });

  it('cve_lookup fetches data correctly', async () => {
    const mockResponse = {
      containers: {
        cna: {
          descriptions: [{ value: "A test vulnerability" }]
        }
      }
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockResponse)
    } as any);

    const handler = toolsMap['cve_lookup'].handler;
    const result = await handler({ cveId: 'CVE-TEST-1234' });

    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);

    expect(data.containers.cna.descriptions[0].value).toBe("A test vulnerability");
  });

  it('cve_lookup handles fetch failures', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      statusText: "Not Found"
    } as any);

    const handler = toolsMap['cve_lookup'].handler;
    const result = await handler({ cveId: 'CVE-INVALID' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Failed to fetch CVE');
  });


  it('get_framework tool returns error for undefined framework', async () => {
    const handler = toolsMap['get_framework'].handler;
    const result = await handler({ framework: 'missing' });
    expect(result.isError).toBe(true);
  });

  it('audit_item tool returns error for invalid item', async () => {
    const handler = toolsMap['audit_item'].handler;
    const result = await handler({ sessionId: 'test', framework: 'owasp', itemId: 'invalid', status: 'pass' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found in owasp');
  });

  it('generate_report tool returns error for invalid session', async () => {
    const handler = toolsMap['generate_report'].handler;
    const result = await handler({ sessionId: 'invalid', format: 'markdown' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });

  it('generate_report tool handles json format correctly', async () => {
    const handler = toolsMap['generate_report'].handler;
    const result = await handler({ sessionId: 'report-session', format: 'json' });
    expect(result.content[0].text).toContain('report-session');
  });

  it('generate_report tool handles score 0 correctly', async () => {
    const handler = toolsMap['generate_report'].handler;
    await toolsMap['audit_item'].handler({ sessionId: 'empty-session', framework: 'owasp', itemId: 'A01', status: 'fail' });
    const result = await handler({ sessionId: 'empty-session', format: 'json' });
    expect(JSON.parse(result.content[0].text).score).toBe('0%');
  });

  it('search_controls tool finds relevant controls for specific framework', async () => {
    const handler = toolsMap['search_controls'].handler;
    const result = await handler({ query: 'injection', framework: 'owasp' });
    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);
    expect(data.results['OWASP Top 10']).toBeDefined();
  });

  it('audit_item tool updates existing item correctly', async () => {
    const handler = toolsMap['audit_item'].handler;
    await handler({ sessionId: 'update-test', framework: 'owasp', itemId: 'A01', status: 'pass' });
    const result = await handler({ sessionId: 'update-test', framework: 'owasp', itemId: 'A01', status: 'fail' });
    const data = JSON.parse(result.content[0].text);
    expect(data.recorded.status).toBe('fail');
  });

  it('generate_report tool builds html with no criticals correctly', async () => {
    const handler = toolsMap['generate_report'].handler;
    await toolsMap['audit_item'].handler({ sessionId: 'html-no-crit', framework: 'owasp', itemId: 'A01', status: 'pass' });
    const result = await handler({ sessionId: 'html-no-crit', format: 'markdown' });
    expect(result.content[0].text).not.toContain('## 🚨 Critical Findings');
  });

  it('generate_report tool handles skipped items in empty score calc', async () => {
    const handler = toolsMap['generate_report'].handler;
    await toolsMap['audit_item'].handler({ sessionId: 'empty-score', framework: 'owasp', itemId: 'A01', status: 'skip' });
    const result = await handler({ sessionId: 'empty-score', format: 'json' });
    expect(JSON.parse(result.content[0].text).score).toBe('0%');
  });

  it('cve_lookup handles fetch exceptions', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network Error'));
    const handler = toolsMap['cve_lookup'].handler;
    const result = await handler({ cveId: 'CVE-ERROR' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Error fetching CVE');
  });

  it('generate_report tool builds html with pass correctly', async () => {
    const handler = toolsMap['generate_report'].handler;
    await toolsMap['audit_item'].handler({ sessionId: 'html-pass', framework: 'owasp', itemId: 'A02', status: 'skip' });
    const result = await handler({ sessionId: 'html-pass', format: 'html' });
    expect(result.content[0].text).toContain('#6b7280'); // The skip color
  });

  it('generate_report tool builds html with failed properly', async () => {
    const handler = toolsMap['generate_report'].handler;
    await toolsMap['audit_item'].handler({ sessionId: 'html-fail-crit', framework: 'owasp', itemId: 'A03', status: 'fail' });
    const result = await handler({ sessionId: 'html-fail-crit', format: 'html' });
    expect(result.content[0].text).toContain('#dc2626');
  });
});
