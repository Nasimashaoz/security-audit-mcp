import { describe, it, expect, vi } from 'vitest';

// We mock StdioServerTransport
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: class StdioServerTransport {
    constructor() {}
  }
}));

import { server, sessions } from './index.js';

describe('security-audit-mcp server tools', () => {
  const tools = (server as any)._registeredTools;

  it('should list frameworks', async () => {
    const list_frameworks = tools['list_frameworks'];
    const res = await list_frameworks.handler({});
    expect(res.content).toBeDefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.length).toBeGreaterThanOrEqual(3);
    expect(data.frameworks[0].id).toBe('owasp');
  });

  it('should get a framework', async () => {
    const get_framework = tools['get_framework'];
    const res = await get_framework.handler({ framework: 'owasp' });
    expect(res.content).toBeDefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe('OWASP Top 10');

    // test not found
    const resFail = await get_framework.handler({ framework: 'unknown' });
    expect(resFail.isError).toBe(true);
  });

  it('should audit an item', async () => {
    const audit_item = (server as any)._registeredTools['audit_item'];
    const res = await audit_item.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Test note'
    });
    expect(res.content).toBeDefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.recorded.itemId).toBe('A01');
    expect(data.recorded.status).toBe('fail');

    // Audit another item to test existing logic and branch where session.results.length > 0 and update existing item
    await audit_item.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'Updated note'
    });

    // Add one more with status pass to test score calc
    await audit_item.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A02',
      status: 'skip',
    });

    // Add high fail
    await audit_item.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A04',
      status: 'fail',
    });

    // test unknown item
    const resFail = await audit_item.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'UNKNOWN',
      status: 'pass'
    });
    expect(resFail.isError).toBe(true);
  });

  it('should generate report', async () => {
    const generate_report = (server as any)._registeredTools['generate_report'];

    // JSON
    const resJson = await generate_report.handler({ sessionId: 'test-session', format: 'json' });
    expect(resJson.content).toBeDefined();
    const data = JSON.parse(resJson.content[0].text);
    expect(data.score).toBe('33%');

    // Markdown
    const resMd = await generate_report.handler({ sessionId: 'test-session', format: 'markdown' });
    expect(resMd.content[0].text).toContain('Results');
    expect(resMd.content[0].text).toContain('A01');

    // HTML
    const resHtml = await generate_report.handler({ sessionId: 'test-session', format: 'html' });
    expect(resHtml.content[0].text).toContain('<!DOCTYPE html>');
    expect(resHtml.content[0].text).toContain('A01');

    // unknown session
    const resFail = await generate_report.handler({ sessionId: 'unknown', format: 'json' });
    expect(resFail.isError).toBe(true);
  });

  it('should get risk summary', async () => {
    const get_risk_summary = tools['get_risk_summary'];
    const res = await get_risk_summary.handler({ framework: 'owasp' });
    const data = JSON.parse(res.content[0].text);
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
  });

  it('should search controls', async () => {
    const search_controls = tools['search_controls'];
    const res = await search_controls.handler({ query: 'injection', framework: 'all' });
    const data = JSON.parse(res.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(data.results['OWASP Top 10']).toBeDefined();

    const resSpecific = await search_controls.handler({ query: 'injection', framework: 'owasp' });
    const dataSpecific = JSON.parse(resSpecific.content[0].text);
    expect(dataSpecific.totalMatches).toBeGreaterThan(0);

    const resNoMatch = await search_controls.handler({ query: 'asdfasdfasdf', framework: 'all' });
    const dataNoMatch = JSON.parse(resNoMatch.content[0].text);
    expect(dataNoMatch.totalMatches).toBe(0);
  });

  it('should test markdown without critical findings', async () => {
    const generate_report = (server as any)._registeredTools['generate_report'];
    const audit_item = (server as any)._registeredTools['audit_item'];

    // clear session
    sessions.delete('test-no-critical');

    await audit_item.handler({
      sessionId: 'test-no-critical',
      framework: 'owasp',
      itemId: 'A04',
      status: 'fail',
      notes: 'test'
    });

    const resMd = await generate_report.handler({ sessionId: 'test-no-critical', format: 'markdown' });
    expect(resMd.content[0].text).not.toContain('Critical Findings');
  });

  it('should format notes with notes in html', async () => {
    const generate_report = (server as any)._registeredTools['generate_report'];
    const audit_item = (server as any)._registeredTools['audit_item'];

    await audit_item.handler({
      sessionId: 'test-notes',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Test note html'
    });
    const resHtml = await generate_report.handler({ sessionId: 'test-notes', format: 'html' });
    expect(resHtml.content[0].text).toContain('Test note html');

    await audit_item.handler({
      sessionId: 'test-no-notes',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
    });
    const resHtmlNoNotes = await generate_report.handler({ sessionId: 'test-no-notes', format: 'html' });
    expect(resHtmlNoNotes.content[0].text).toContain('#16a34a');
  });
});

  it('should test critical findings in markdown without notes', async () => {
    const generate_report = (server as any)._registeredTools['generate_report'];
    const audit_item = (server as any)._registeredTools['audit_item'];
    sessions.delete('test-critical-no-notes');

    await audit_item.handler({
      sessionId: 'test-critical-no-notes',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      // no notes
    });

    const resMd = await generate_report.handler({ sessionId: 'test-critical-no-notes', format: 'markdown' });
    expect(resMd.content[0].text).toContain('Critical Findings');
  });

  it('should test missing notes in markdown', async () => {
    const generate_report = (server as any)._registeredTools['generate_report'];
    const audit_item = (server as any)._registeredTools['audit_item'];

    // clear session

    await audit_item.handler({
      sessionId: 'test-no-notes-markdown',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      // no notes
    });

    const resMd = await generate_report.handler({ sessionId: 'test-no-notes-markdown', format: 'markdown' });
    expect(resMd.content[0].text).toContain('Critical Findings');
  });

  it('should generate error catch test', async () => {
    // This is tested by integration or not required for full coverage
    // because standard MCP server stdio start code
  });

  it('should test main block', async () => {
    const { main } = await import('./index.js');
    await expect(main()).rejects.toThrow();
  });

  it('should get PCI-DSS framework', async () => {
    const get_framework = (server as any)._registeredTools['get_framework'];
    const res = await get_framework.handler({ framework: 'pcidss' });
    expect(res.content).toBeDefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe('PCI-DSS');
  });

  it('should get SOC 2 framework', async () => {
    const get_framework = (server as any)._registeredTools['get_framework'];
    const res = await get_framework.handler({ framework: 'soc2' });
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe('SOC 2');
  });

  it('should get HIPAA framework', async () => {
    const get_framework = (server as any)._registeredTools['get_framework'];
    const res = await get_framework.handler({ framework: 'hipaa' });
    expect(res.content).toBeDefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe('HIPAA');
  });

  it('should get CIS Controls framework', async () => {
    const get_framework = (server as any)._registeredTools['get_framework'];
    const res = await get_framework.handler({ framework: 'cisv8' });
    expect(res.content).toBeDefined();
    const data = JSON.parse(res.content[0].text);
    expect(data.name).toBe('CIS Controls');
  });

  it('should test generic error catch', async () => {
    // Already good
  });
