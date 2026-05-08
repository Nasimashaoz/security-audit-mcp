import { describe, it, expect, vi } from 'vitest';
import { server } from './index.js';
import { FRAMEWORKS } from './frameworks.js';

// Mock StdioServerTransport
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        connect: vi.fn(),
        close: vi.fn(),
      };
    }),
  };
});

describe('MCP Server Tools', () => {
  const tools = (server as any)._registeredTools;

  it('should have all expected tools registered', () => {
    expect(tools).toHaveProperty('list_frameworks');
    expect(tools).toHaveProperty('get_framework');
    expect(tools).toHaveProperty('audit_item');
    expect(tools).toHaveProperty('generate_report');
    expect(tools).toHaveProperty('get_risk_summary');
    expect(tools).toHaveProperty('search_controls');
  });

  describe('list_frameworks', () => {
    it('should list all available frameworks', async () => {
      const handler = tools['list_frameworks']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({});
      expect(result.content[0].type).toBe('text');

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks).toBeInstanceOf(Array);
      expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(parsed.frameworks[0]).toHaveProperty('id');
      expect(parsed.frameworks[0]).toHaveProperty('name');
    });
  });

  describe('get_framework', () => {
    it('should return a specific framework', async () => {
      const handler = tools['get_framework']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({ framework: 'owasp' });
      expect(result.content[0].type).toBe('text');

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe('OWASP Top 10');
      expect(parsed.items).toBeInstanceOf(Array);
      expect(parsed.items.length).toBe(10);
    });

    it('should return an error for an invalid framework', async () => {
      const handler = tools['get_framework']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({ framework: 'invalid' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });
  });

  describe('audit_item', () => {
    it('should record an audit item result', async () => {
      const handler = tools['audit_item']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({
        sessionId: 'test-session-1',
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass',
        notes: 'Looks good'
      });

      expect(result.content[0].type).toBe('text');
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.itemId).toBe('A01');
      expect(parsed.recorded.status).toBe('pass');
      expect(parsed.recorded.notes).toBe('Looks good');
      expect(parsed.sessionProgress).toContain('1 /');
    });

    it('should update an existing audit item', async () => {
      const handler = tools['audit_item']?.handler;
      expect(handler).toBeDefined();

      const sessionId = 'test-session-update';
      await handler({ sessionId, framework: 'owasp', itemId: 'A01', status: 'pass' });
      const result = await handler({ sessionId, framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'Found issue' });

      expect(result.content[0].type).toBe('text');
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.status).toBe('fail');
      expect(parsed.recorded.notes).toBe('Found issue');
      expect(parsed.sessionProgress).toContain('1 /'); // Should still be 1 item
    });

    it('should return an error for an invalid item', async () => {
      const handler = tools['audit_item']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({
        sessionId: 'test-session-invalid',
        framework: 'owasp',
        itemId: 'INVALID-ITEM',
        status: 'pass'
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });
  });

  describe('generate_report', () => {
    it('should generate a json report', async () => {
      // First add some items
      const auditHandler = tools['audit_item']?.handler;
      await auditHandler({ sessionId: 'report-session', framework: 'owasp', itemId: 'A01', status: 'pass' });
      await auditHandler({ sessionId: 'report-session', framework: 'owasp', itemId: 'A02', status: 'fail', notes: 'Bad crypto' });

      const handler = tools['generate_report']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({ sessionId: 'report-session', format: 'json' });
      expect(result.content[0].type).toBe('text');

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.session).toBe('report-session');
      expect(parsed.summary.passed).toBe(1);
      expect(parsed.summary.failed).toBe(1);
      expect(parsed.criticalFindings.length).toBe(1);
    });

    it('should generate a markdown report', async () => {
      const handler = tools['generate_report']?.handler;
      const result = await handler({ sessionId: 'report-session', format: 'markdown' });

      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(result.content[0].text).toContain('## 🚨 Critical Findings');
      expect(result.content[0].text).toContain('| A01 |');
    });

    it('should generate an html report', async () => {
      const handler = tools['generate_report']?.handler;
      const result = await handler({ sessionId: 'report-session', format: 'html' });

      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('<!DOCTYPE html>');
      expect(result.content[0].text).toContain('<td>A01</td>');
    });

    it('should return an error for a non-existent session', async () => {
      const handler = tools['generate_report']?.handler;
      const result = await handler({ sessionId: 'non-existent', format: 'json' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });
  });

  describe('get_risk_summary', () => {
    it('should return a risk summary for a framework', async () => {
      const handler = tools['get_risk_summary']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({ framework: 'owasp' });
      expect(result.content[0].type).toBe('text');

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.framework).toBe('OWASP Top 10');
      expect(parsed.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
      expect(parsed.riskBreakdown.HIGH).toBeInstanceOf(Array);
      expect(parsed.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe('search_controls', () => {
    it('should search controls across all frameworks', async () => {
      const handler = tools['search_controls']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({ query: 'encrypt', framework: 'all' });
      expect(result.content[0].type).toBe('text');

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.query).toBe('encrypt');
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(parsed.results).length).toBeGreaterThan(0);
    });

    it('should search controls in a specific framework', async () => {
      const handler = tools['search_controls']?.handler;
      const result = await handler({ query: 'access', framework: 'owasp' });

      expect(result.content[0].type).toBe('text');
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(parsed.results).length).toBe(1);
      expect(Object.keys(parsed.results)[0]).toBe('OWASP Top 10');
    });
  });
});
