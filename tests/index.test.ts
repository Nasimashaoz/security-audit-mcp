import { describe, it, expect, vi, beforeAll } from 'vitest';
import { server } from '../src/index.js';
import { FRAMEWORKS } from '../src/frameworks.js';

// Mock the StdioServerTransport module correctly for ES modules
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      start() { return Promise.resolve(); }
      close() { return Promise.resolve(); }
      send() { return Promise.resolve(); }
    }
  };
});

describe('MCP Server Tools', () => {

  // Create an instance of the tools array or object
  const getTool = (name: string) => {
    // The McpServer exposes tools either through an internal property
    // We'll cast to access it
    const tools = (server as any)._registeredTools || (server as any).tools;
    if (Array.isArray(tools)) {
      return tools.find(t => t.name === name);
    }
    // If it's a map or object
    if (tools instanceof Map) {
       return tools.get(name);
    }
    return tools[name];
  };

  it('list_frameworks should return a list of all frameworks', async () => {
    const tool = getTool('list_frameworks');
    expect(tool).toBeDefined();

    // Execute tool handler
    // Handlers usually take an object for args, but list_frameworks has none
    const result = await tool.handler({});

    // Result typically has content array
    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');

    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.frameworks).toBeDefined();
    expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
  });

  it('get_framework should return specific framework checklist', async () => {
    const tool = getTool('get_framework');

    const result = await tool.handler({ framework: 'owasp' }, { _rawArgs: {} });
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.name).toBe('OWASP Top 10');
    expect(parsed.items.length).toBeGreaterThan(0);
  });

  it('audit_item should record result and generate_report should output CSV', async () => {
    const auditTool = getTool('audit_item');
    const reportTool = getTool('generate_report');

    const sessionId = 'test-session-123';

    // Audit an item
    const auditResult = await auditTool.handler({
      sessionId,
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Test note with "quotes"'
    }, { _rawArgs: {} });

    const parsedAudit = JSON.parse(auditResult.content[0].text);
    expect(parsedAudit.recorded.status).toBe('fail');

    // Generate CSV report
    const reportResult = await reportTool.handler({
      sessionId,
      format: 'csv'
    }, { _rawArgs: {} });

    const csvContent = reportResult.content[0].text;
    expect(csvContent).toContain('ID,Title,Risk,Status,Notes');
    expect(csvContent).toContain('A01');
    expect(csvContent).toContain('FAIL');
    expect(csvContent).toContain('Test note with ""quotes""');
  });

  it('get_risk_summary should return breakdown of risks', async () => {
    const tool = getTool('get_risk_summary');

    const result = await tool.handler({ framework: 'owasp' }, { _rawArgs: {} });
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
    expect(parsed.riskBreakdown.HIGH).toBeDefined();
  });

  it('search_controls should find controls by keyword', async () => {
    const tool = getTool('search_controls');

    const result = await tool.handler({ query: 'access', framework: 'all' }, { _rawArgs: {} });
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(parsed.results['OWASP Top 10']).toBeDefined();
  });

});
