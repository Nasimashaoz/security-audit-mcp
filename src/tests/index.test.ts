import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from '../index.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class MockStdioServerTransport {
      start() {}
      close() {}
    }
  }
});

// Helper to access registered tools
function getTool(name: string) {
  const toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
  return toolsMap[name];
}

describe('security-audit-mcp tools', () => {
  it('list_frameworks', async () => {
    const tool = getTool('list_frameworks');
    expect(tool).toBeDefined();

    const result = await tool.handler({});
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.frameworks.length).toBeGreaterThan(0);
  });

  it('get_framework', async () => {
    const tool = getTool('get_framework');
    expect(tool).toBeDefined();

    const result = await tool.handler({ framework: 'owasp' });
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.name).toBe('OWASP Top 10');

    const badResult = await tool.handler({ framework: 'invalid_fw' });
    expect(badResult.isError).toBe(true);
  });

  it('audit_item', async () => {
    const tool = getTool('audit_item');
    expect(tool).toBeDefined();

    // Valid item
    const validResult = await tool.handler({ sessionId: 'session1', framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'test notes' });
    expect(validResult.content[0].type).toBe('text');
    const validParsed = JSON.parse(validResult.content[0].text);
    expect(validParsed.recorded.itemId).toBe('A01');
    expect(validParsed.recorded.status).toBe('fail');

    // Invalid item
    const invalidResult = await tool.handler({ sessionId: 'session1', framework: 'owasp', itemId: 'invalid_id', status: 'fail' });
    expect(invalidResult.isError).toBe(true);

    // Update existing item
    const updateResult = await tool.handler({ sessionId: 'session1', framework: 'owasp', itemId: 'A01', status: 'pass' });
    const updateParsed = JSON.parse(updateResult.content[0].text);
    expect(updateParsed.recorded.status).toBe('pass');
  });

  it('generate_report', async () => {
    const tool = getTool('generate_report');
    expect(tool).toBeDefined();

    // Invalid session
    const invalidResult = await tool.handler({ sessionId: 'invalid_session', format: 'markdown' });
    expect(invalidResult.isError).toBe(true);

    // Valid session (created in audit_item test)
    const jsonResult = await tool.handler({ sessionId: 'session1', format: 'json' });
    const jsonParsed = JSON.parse(jsonResult.content[0].text);
    expect(jsonParsed.session).toBe('session1');
    expect(jsonParsed.score).toBe('100%'); // 1 pass, 0 fail/skip

    const mdResult = await tool.handler({ sessionId: 'session1', format: 'markdown' });
    expect(mdResult.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(mdResult.content[0].text).toContain('100%');

    const htmlResult = await tool.handler({ sessionId: 'session1', format: 'html' });
    expect(htmlResult.content[0].text).toContain('<!DOCTYPE html>');
    expect(htmlResult.content[0].text).toContain('100%');
  });

  it('get_risk_summary', async () => {
    const tool = getTool('get_risk_summary');
    expect(tool).toBeDefined();

    const result = await tool.handler({ framework: 'owasp' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.framework).toBe('OWASP Top 10');
    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
  });

  it('search_controls', async () => {
    const tool = getTool('search_controls');
    expect(tool).toBeDefined();

    const resultAll = await tool.handler({ query: 'access', framework: 'all' });
    const parsedAll = JSON.parse(resultAll.content[0].text);
    expect(parsedAll.totalMatches).toBeGreaterThan(0);
    expect(parsedAll.results['OWASP Top 10']).toBeDefined();

    const resultOwasp = await tool.handler({ query: 'access', framework: 'owasp' });
    const parsedOwasp = JSON.parse(resultOwasp.content[0].text);
    expect(parsedOwasp.totalMatches).toBeGreaterThan(0);
    expect(parsedOwasp.results['NIST SP 800-53']).toBeUndefined();
  });
  it('generate_report with critical failure', async () => {
    const auditTool = getTool('audit_item');
    // Add a critical fail to session1
    await auditTool.handler({ sessionId: 'session1', framework: 'owasp', itemId: 'A01', status: 'fail' });

    const reportTool = getTool('generate_report');
    const mdResult = await reportTool.handler({ sessionId: 'session1', format: 'markdown' });
    expect(mdResult.content[0].text).toContain('🚨 Critical Findings');
  });

  it('generate_report edge cases', async () => {
    const reportTool = getTool('generate_report');


  });
  it('main function', async () => {
    const { main } = await import('../index.js');
    await main();
  });

  it('cve_lookup success', async () => {
    const tool = getTool('cve_lookup');
    expect(tool).toBeDefined();

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        cveMetadata: { cveId: 'CVE-2021-44228' }
      })
    });

    const result = await tool.handler({ cveId: 'CVE-2021-44228' });
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.cveMetadata.cveId).toBe('CVE-2021-44228');
  });

  it('cve_lookup not found', async () => {
    const tool = getTool('cve_lookup');
    expect(tool).toBeDefined();

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404
    });

    const result = await tool.handler({ cveId: 'CVE-9999-99999' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });

  it('cve_lookup error', async () => {
    const tool = getTool('cve_lookup');
    expect(tool).toBeDefined();

    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

    const result = await tool.handler({ cveId: 'CVE-2021-44228' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Network error');
  });

  it('cve_lookup server error', async () => {
    const tool = getTool('cve_lookup');
    expect(tool).toBeDefined();

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500
    });

    const result = await tool.handler({ cveId: 'CVE-2021-44228' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('MITRE API returned status: 500');
  });

});
