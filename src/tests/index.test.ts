import { describe, it, expect, vi } from 'vitest';
import { server } from '../index.js';
import { FRAMEWORKS } from '../frameworks.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class StdioServerTransport {
      constructor() {}
      async close() {}
    }
  };
});

describe('MCP Server Tools', () => {
  const tools = (server as any)._registeredTools;

  it('list_frameworks tool', async () => {
    const handler = tools['list_frameworks'].handler;
    const result = await handler({});
    const content = JSON.parse(result.content[0].text);
    expect(content.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    expect(content.frameworks[0]).toHaveProperty('id', 'owasp');
  });

  it('get_framework tool', async () => {
    const handler = tools['get_framework'].handler;
    const result = await handler({ framework: 'owasp' });
    const content = JSON.parse(result.content[0].text);
    expect(content.name).toBe('OWASP Top 10');
    expect(content.items.length).toBeGreaterThan(0);
  });

  it('get_framework tool - non-existent', async () => {
    const handler = tools['get_framework'].handler;
    const result = await handler({ framework: 'nonexistent' });
    expect(result.isError).toBe(true);
  });

  it('audit_item tool', async () => {
    const handler = tools['audit_item'].handler;
    const result = await handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'Test passed'
    });
    const content = JSON.parse(result.content[0].text);
    expect(content.recorded.itemId).toBe('A01');
    expect(content.recorded.status).toBe('pass');
  });

  it('audit_item tool - item not found', async () => {
    const handler = tools['audit_item'].handler;
    const result = await handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A99',
      status: 'pass'
    });
    expect(result.isError).toBe(true);
  });

  it('generate_report tool', async () => {
    const handler = tools['generate_report'].handler;
    const result = await handler({ sessionId: 'test-session', format: 'json' });
    const content = JSON.parse(result.content[0].text);
    expect(content.session).toBe('test-session');
    expect(content.summary.passed).toBe(1);
  });

  it('generate_report tool - unknown session', async () => {
    const handler = tools['generate_report'].handler;
    const result = await handler({ sessionId: 'unknown', format: 'json' });
    expect(result.isError).toBe(true);
  });

  it('get_session_status tool', async () => {
    const handler = tools['get_session_status'].handler;
    const result = await handler({ sessionId: 'test-session' });
    const content = JSON.parse(result.content[0].text);
    expect(content.sessionId).toBe('test-session');
    expect(content.summary.passed).toBe(1);
  });

  it('get_session_status tool - unknown session', async () => {
    const handler = tools['get_session_status'].handler;
    const result = await handler({ sessionId: 'unknown' });
    expect(result.isError).toBe(true);
  });

  it('get_risk_summary tool', async () => {
    const handler = tools['get_risk_summary'].handler;
    const result = await handler({ framework: 'owasp' });
    const content = JSON.parse(result.content[0].text);
    expect(content.framework).toBe('OWASP Top 10');
    expect(content.riskBreakdown).toHaveProperty('CRITICAL');
  });

  it('search_controls tool', async () => {
    const handler = tools['search_controls'].handler;
    const result = await handler({ query: 'access', framework: 'all' });
    const content = JSON.parse(result.content[0].text);
    expect(content.query).toBe('access');
    expect(content.totalMatches).toBeGreaterThan(0);
  });
});
