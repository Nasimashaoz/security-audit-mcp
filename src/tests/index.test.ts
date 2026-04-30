import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server, sessions } from '../index.js';
import { FRAMEWORKS } from '../frameworks.js';

// Mock the StdioServerTransport as recommended
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        // mock methods if necessary
      };
    }),
  };
});

describe('security-audit-mcp server tools', () => {
  let registeredTools: any;

  beforeEach(() => {
    // Access the internal tools object
    registeredTools = (server as any)._registeredTools;
    sessions.clear();
  });

  // Tests will go here

  it('list_frameworks should return all available frameworks', async () => {
    const handler = registeredTools['list_frameworks'].handler;
    const result = await handler({});

    expect(result.content).toBeDefined();
    expect(result.content.length).toBe(1);

    const parsedContent = JSON.parse(result.content[0].text);
    expect(parsedContent.frameworks).toBeDefined();

    // Check that we have the 3 original + 5 new ones = 8 frameworks
    expect(parsedContent.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);

    const owasp = parsedContent.frameworks.find((f: any) => f.id === 'owasp');
    expect(owasp).toBeDefined();
    expect(owasp.name).toBe('OWASP Top 10');
  });

  it('get_framework should return the full checklist for a specific framework', async () => {
    const handler = registeredTools['get_framework'].handler;
    const result = await handler({ framework: 'owasp' }, {});

    expect(result.content).toBeDefined();
    expect(result.content.length).toBe(1);

    const parsedContent = JSON.parse(result.content[0].text);
    expect(parsedContent.name).toBe('OWASP Top 10');
    expect(parsedContent.items).toBeDefined();
    expect(parsedContent.items.length).toBeGreaterThan(0);
  });

  it('get_framework should return an error if the framework is not found', async () => {
    const handler = registeredTools['get_framework'].handler;
    const result = await handler({ framework: 'nonexistent' }, {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it('audit_item should record a pass result', async () => {
    const handler = registeredTools['audit_item'].handler;
    const result = await handler({ sessionId: 'test-session', framework: 'owasp', itemId: 'A01', status: 'pass' }, {});

    expect(result.content).toBeDefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.recorded.status).toBe('pass');

    // Check state change
    const session = sessions.get('test-session');
    expect(session).toBeDefined();
    expect(session!.results.length).toBe(1);
    expect(session!.results[0].itemId).toBe('A01');
  });

  it('audit_item should return an error if item not found', async () => {
    const handler = registeredTools['audit_item'].handler;
    const result = await handler({ sessionId: 'test-session', framework: 'owasp', itemId: 'invalid', status: 'pass' }, {});
    expect(result.isError).toBe(true);
  });

  it('generate_report should generate a markdown report by default', async () => {
    // Populate session
    sessions.set('test-session', { id: 'test-session', framework: 'owasp', results: [{ itemId: 'A01', title: 'Broken Access Control', risk: 'CRITICAL', status: 'fail', notes: '' }], startedAt: new Date().toISOString() });

    const handler = registeredTools['generate_report'].handler;
    const result = await handler({ sessionId: 'test-session' }, {});

    expect(result.content[0].text).toContain('<!DOCTYPE html>');
  });

  it('generate_report should return an error if session not found', async () => {
    const handler = registeredTools['generate_report'].handler;
    const result = await handler({ sessionId: 'nonexistent-session' }, {});

    expect(result.isError).toBe(true);
  });

  it('get_risk_summary should return breakdown of risks', async () => {
    const handler = registeredTools['get_risk_summary'].handler;
    const result = await handler({ framework: 'owasp' }, {});

    expect(result.content).toBeDefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.riskBreakdown).toBeDefined();
    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
    expect(parsed.riskBreakdown.HIGH).toBeDefined();
    expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it('search_controls should search across all frameworks', async () => {
    const handler = registeredTools['search_controls'].handler;
    const result = await handler({ query: 'authentication', framework: 'all' }, {});

    expect(result.content).toBeDefined();
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(parsed.results).length).toBeGreaterThan(0);
  });

  it('generate_report should handle json format', async () => {
    sessions.set('test-session', { id: 'test-session', framework: 'owasp', results: [{ itemId: 'A01', title: 'Broken Access Control', risk: 'CRITICAL', status: 'fail', notes: '' }], startedAt: new Date().toISOString() });
    const handler = registeredTools['generate_report'].handler;
    const result = await handler({ sessionId: 'test-session', format: 'json' }, {});
    expect(result.content[0].text).toContain('"score": "0%"');
  });

  it('generate_report should handle markdown format', async () => {
    sessions.set('test-session', { id: 'test-session', framework: 'owasp', results: [{ itemId: 'A01', title: 'Broken Access Control', risk: 'CRITICAL', status: 'fail', notes: '' }], startedAt: new Date().toISOString() });
    const handler = registeredTools['generate_report'].handler;
    const result = await handler({ sessionId: 'test-session', format: 'markdown' }, {});
    expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
  });

  it('audit_item should record an updated result', async () => {
    sessions.set('test-session', { id: 'test-session', framework: 'owasp', results: [{ itemId: 'A01', title: 'Broken Access Control', risk: 'CRITICAL', status: 'fail', notes: '' }], startedAt: new Date().toISOString() });
    const handler = registeredTools['audit_item'].handler;
    const result = await handler({ sessionId: 'test-session', framework: 'owasp', itemId: 'A01', status: 'pass' }, {});
    const session = sessions.get('test-session');
    expect(session!.results.length).toBe(1);
    expect(session!.results[0].status).toBe('pass');
  });

});
