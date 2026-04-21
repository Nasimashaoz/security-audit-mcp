import { describe, it, expect, vi } from 'vitest';
import { server } from './index.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn().mockImplementation(() => ({})),
}));

describe('MCP Server Tools', () => {
  const getTool = (name: string) => {
    return (server as any)._registeredTools?.[name];
  };

  it('should list all frameworks', async () => {
    const listFrameworks = getTool('list_frameworks');
    expect(listFrameworks).toBeDefined();

    // Using the tool's handler
    const response = await listFrameworks.handler({});

    expect(response).toBeDefined();
    expect(response.content).toBeDefined();
    expect(response.content[0].type).toBe('text');

    const data = JSON.parse(response.content[0].text);
    expect(data.frameworks).toBeDefined();
    // owasp, nist, iso27001, pcidss, soc2, hipaa, cisv8
    expect(data.frameworks.length).toBe(7);

    const owasp = data.frameworks.find((f: any) => f.id === 'owasp');
    expect(owasp).toBeDefined();
    expect(owasp.itemCount).toBe(10);
  });

  it('should get a specific framework', async () => {
    const getFramework = getTool('get_framework');

    const response = await getFramework.handler({ framework: 'owasp' });
    expect(response.isError).toBeUndefined(); // or false

    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe('OWASP Top 10');
    expect(data.items.length).toBe(10);
  });

  it('should return error for invalid framework in get_framework', async () => {
    const getFramework = getTool('get_framework');

    const response = await getFramework.handler({ framework: 'invalid_framework' });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it('should audit an item and generate a report', async () => {
    const auditItem = getTool('audit_item');
    const generateReport = getTool('generate_report');

    const sessionId = 'test-session-1';

    // Audit a valid item
    let response = await auditItem.handler({
      sessionId,
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Found an issue'
    });

    expect(response.isError).toBeUndefined();
    expect(response.content[0].text).toContain('A01');

    // Generate JSON report
    response = await generateReport.handler({
      sessionId,
      format: 'json'
    });

    expect(response.isError).toBeUndefined();
    const reportData = JSON.parse(response.content[0].text);
    expect(reportData.session).toBe(sessionId);
    expect(reportData.score).toBe('0%');
    expect(reportData.summary.failed).toBe(1);
    expect(reportData.criticalFindings.length).toBe(1); // A01 is CRITICAL

    // Generate CSV report
    response = await generateReport.handler({
      sessionId,
      format: 'csv'
    });
    expect(response.isError).toBeUndefined();
    expect(response.content[0].text).toContain('ID,Title,Risk,Status,Notes\n"A01",');
  });

  it('should get risk summary', async () => {
    const getRiskSummary = getTool('get_risk_summary');

    const response = await getRiskSummary.handler({ framework: 'owasp' });
    const data = JSON.parse(response.content[0].text);

    expect(data.framework).toBe('OWASP Top 10');
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it('should search controls', async () => {
    const searchControls = getTool('search_controls');

    const response = await searchControls.handler({ query: 'injection', framework: 'all' });
    const data = JSON.parse(response.content[0].text);

    expect(data.query).toBe('injection');
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results['OWASP Top 10']).toBeDefined();
  });
});
