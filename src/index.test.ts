import { describe, it, expect } from 'vitest';
import { server } from './index.js';
import { FRAMEWORKS } from './frameworks.js';

describe('security-audit-mcp tools', () => {
  it('list_frameworks should return all frameworks', async () => {
    const tools = (server as any)._registeredTools;
    const handler = tools['list_frameworks'].handler;
    const result = await handler({}, { request: {} as any });
    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.frameworks).toBeDefined();
    expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
  });

  it('get_framework should return specific framework details', async () => {
    const tools = (server as any)._registeredTools;
    const handler = tools['get_framework'].handler;
    const result = await handler({ framework: 'owasp' }, { request: {} as any });
    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.name).toBe('OWASP Top 10');
  });

  it('get_framework should handle missing framework gracefully', async () => {
    const tools = (server as any)._registeredTools;
    const handler = tools['get_framework'].handler;
    // @ts-ignore - bypassing zod validation intentionally for unit test
    const result = await handler({ framework: 'nonexistent' }, { request: {} as any });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });

  it('audit_item should record item status', async () => {
    const tools = (server as any)._registeredTools;
    const handler = tools['audit_item'].handler;
    const result = await handler({
      sessionId: 'test-session-1',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'LGTM'
    }, { request: {} as any });

    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.recorded.itemId).toBe('A01');
    expect(parsed.recorded.status).toBe('pass');
    expect(parsed.recorded.notes).toBe('LGTM');
  });

  it('audit_item should error on missing item', async () => {
    const tools = (server as any)._registeredTools;
    const handler = tools['audit_item'].handler;
    const result = await handler({
      sessionId: 'test-session-1',
      framework: 'owasp',
      itemId: 'A99',
      status: 'pass'
    }, { request: {} as any });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });

  it('generate_report should generate a summary for a given session', async () => {
    const tools = (server as any)._registeredTools;
    // Pre-populate with an audit item
    await tools['audit_item'].handler({
      sessionId: 'test-session-2',
      framework: 'iso27001',
      itemId: 'A.5.1',
      status: 'fail',
      notes: 'missing policy'
    }, { request: {} as any });

    const handler = tools['generate_report'].handler;
    const result = await handler({ sessionId: 'test-session-2', format: 'json' }, { request: {} as any });

    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.framework).toBe('ISO 27001');
    expect(parsed.summary.failed).toBe(1);
    expect(parsed.allResults[0].itemId).toBe('A.5.1');
  });

  it('generate_report should error for unknown session', async () => {
    const tools = (server as any)._registeredTools;
    const handler = tools['generate_report'].handler;
    const result = await handler({ sessionId: 'unknown-session', format: 'json' }, { request: {} as any });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('not found');
  });

  it('get_risk_summary should return breakdown of risks', async () => {
    const tools = (server as any)._registeredTools;
    const handler = tools['get_risk_summary'].handler;
    const result = await handler({ framework: 'nist' }, { request: {} as any });

    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.framework).toBe('NIST SP 800-53');
    expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(parsed.riskBreakdown.HIGH.length).toBeGreaterThan(0);
  });

  it('search_controls should find controls by keyword', async () => {
    const tools = (server as any)._registeredTools;
    const handler = tools['search_controls'].handler;
    const result = await handler({ query: 'encryption', framework: 'all' }, { request: {} as any });

    expect(result.content).toBeDefined();
    expect(result.content[0].type).toBe('text');
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(parsed.results).toBeDefined();
  });
});
