import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from '../src/index.js';
import { FRAMEWORKS } from '../src/frameworks.js';

describe('MCP Server', () => {
  let tools: Record<string, any>;

  beforeEach(() => {
    tools = (server as any)._registeredTools;
  });

  it('should have all tools registered', () => {
    expect(tools.list_frameworks).toBeDefined();
    expect(tools.get_framework).toBeDefined();
    expect(tools.audit_item).toBeDefined();
    expect(tools.generate_report).toBeDefined();
    expect(tools.get_risk_summary).toBeDefined();
    expect(tools.search_controls).toBeDefined();
  });

  it('list_frameworks should return all available frameworks', async () => {
    const handler = tools.list_frameworks.handler;
    const result = await handler({});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.frameworks).toBeDefined();
    expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
    expect(parsed.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
    expect(parsed.frameworks.some((f: any) => f.id === 'pcidss')).toBe(true);
  });

  it('get_framework should return a specific framework', async () => {
    const handler = tools.get_framework.handler;
    const result = await handler({ framework: 'owasp' }, {});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.name).toBe('OWASP Top 10');
    expect(parsed.items.length).toBeGreaterThan(0);
  });

  it('get_framework should return error for unknown framework', async () => {
    const handler = tools.get_framework.handler;
    const result = await handler({ framework: 'unknown' }, {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it('audit_item should record result and progress', async () => {
    const handler = tools.audit_item.handler;
    const args = {
      sessionId: 'test-session-1',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'LGTM'
    };

    const result = await handler(args, {});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.recorded).toBeDefined();
    expect(parsed.recorded.status).toBe('pass');
    expect(parsed.sessionProgress).toContain('items audited');
  });

  it('audit_item should return error for unknown item', async () => {
    const handler = tools.audit_item.handler;
    const args = {
      sessionId: 'test-session-2',
      framework: 'owasp',
      itemId: 'Z99',
      status: 'pass'
    };

    const result = await handler(args, {});
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it('generate_report should return json format', async () => {
    const handler = tools.generate_report.handler;

    // Ensure we have a session first
    await tools.audit_item.handler({
      sessionId: 'test-session-3',
      framework: 'nist',
      itemId: 'AC-1',
      status: 'fail'
    }, {});

    const result = await handler({ sessionId: 'test-session-3', format: 'json' }, {});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.framework).toBe('NIST SP 800-53');
    expect(parsed.summary.failed).toBe(1);
    expect(parsed.score).toBe('0%');
  });

  it('generate_report should return markdown format', async () => {
    const handler = tools.generate_report.handler;

    // Add critical fail to trigger critical section
    await tools.audit_item.handler({
      sessionId: 'test-session-3-md',
      framework: 'nist',
      itemId: 'AC-6',
      status: 'fail',
      notes: 'Too permissive'
    }, {});

    const result = await handler({ sessionId: 'test-session-3-md', format: 'markdown' }, {});
    expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(result.content[0].text).toContain('🚨 Critical Findings');
    expect(result.content[0].text).toContain('AC-6');
  });

  it('generate_report should return html format', async () => {
    const handler = tools.generate_report.handler;

    await tools.audit_item.handler({
      sessionId: 'test-session-3-html',
      framework: 'nist',
      itemId: 'AC-1',
      status: 'pass'
    }, {});

    const result = await handler({ sessionId: 'test-session-3-html', format: 'html' }, {});
    expect(result.content[0].text).toContain('<!DOCTYPE html>');
    expect(result.content[0].text).toContain('<h1>🔒 Security Audit Report</h1>');
    expect(result.content[0].text).toContain('#16a34a'); // Pass color
  });

  it('generate_report should return error for unknown session', async () => {
    const handler = tools.generate_report.handler;
    const result = await handler({ sessionId: 'unknown-session' }, {});

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("not found");
  });

  it('get_risk_summary should return breakdown of risks', async () => {
    const handler = tools.get_risk_summary.handler;
    const result = await handler({ framework: 'iso27001' }, {});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.framework).toBe('ISO 27001');
    expect(parsed.riskBreakdown.CRITICAL).toBeDefined();
    expect(parsed.riskBreakdown.HIGH).toBeDefined();
    expect(parsed.riskBreakdown.MEDIUM).toBeDefined();
    expect(parsed.riskBreakdown.LOW).toBeDefined();
  });

  it('search_controls should search across all frameworks', async () => {
    const handler = tools.search_controls.handler;
    const result = await handler({ query: 'encryption', framework: 'all' }, {});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.query).toBe('encryption');
    expect(parsed.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(parsed.results).length).toBeGreaterThan(0);
  });

  it('search_controls should search within a specific framework', async () => {
    const handler = tools.search_controls.handler;
    const result = await handler({ query: 'encrypt', framework: 'owasp' }, {});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.query).toBe('encrypt');
    // Results should only have the 'OWASP Top 10' key
    expect(Object.keys(parsed.results).length).toBeGreaterThan(0);
    expect(parsed.results['OWASP Top 10']).toBeDefined();
    expect(Object.keys(parsed.results).every(k => k === 'OWASP Top 10')).toBe(true);
  });
});
