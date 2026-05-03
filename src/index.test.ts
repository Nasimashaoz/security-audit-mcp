import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from './index.js';
import { FRAMEWORKS } from './frameworks.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: vi.fn().mockImplementation(() => ({
    // Mock the required methods for transport
    start: vi.fn(),
    close: vi.fn(),
    send: vi.fn(),
    onmessage: vi.fn(),
    onclose: vi.fn(),
    onerror: vi.fn(),
  })),
}));

describe('Security Audit MCP Server', () => {
  let tools: any;

  beforeEach(() => {
    // Access the registered tools internally
    tools = (server as any)._registeredTools;
  });

  describe('list_frameworks tool', () => {
    it('should list all available frameworks', async () => {
      const handler = tools['list_frameworks']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({});
      expect(result.content[0].type).toBe('text');

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.frameworks).toBeDefined();
      expect(parsed.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);

      // Verify some known frameworks are in the list
      const names = parsed.frameworks.map((f: any) => f.id);
      expect(names).toContain('owasp');
      expect(names).toContain('nist');
      expect(names).toContain('pcidss');
      expect(names).toContain('soc2');
      expect(names).toContain('hipaa');
    });
  });

  describe('get_framework tool', () => {
    it('should return a specific framework', async () => {
      const handler = tools['get_framework']?.handler;
      expect(handler).toBeDefined();

      const result = await handler({ framework: 'owasp' });
      expect(result.content[0].type).toBe('text');

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.name).toBe('OWASP Top 10');
      expect(parsed.items.length).toBeGreaterThan(0);
    });

    it('should return an error for an unknown framework', async () => {
      const handler = tools['get_framework']?.handler;

      const result = await handler({ framework: 'unknown' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Framework 'unknown' not found.");
    });
  });

  describe('audit_item tool', () => {
    const sessionId = 'test-session-123';

    it('should return an error if item is not found', async () => {
      const handler = tools['audit_item']?.handler;
      const result = await handler({
        sessionId,
        framework: 'owasp',
        itemId: 'INVALID',
        status: 'pass'
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Item 'INVALID' not found in owasp.");
    });

    it('should record an audit result successfully', async () => {
      const handler = tools['audit_item']?.handler;
      const result = await handler({
        sessionId,
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Failed access control'
      });

      expect(result.isError).toBeUndefined();
      expect(result.content[0].type).toBe('text');

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded).toBeDefined();
      expect(parsed.recorded.itemId).toBe('A01');
      expect(parsed.recorded.status).toBe('fail');
      expect(parsed.recorded.notes).toBe('Failed access control');
      expect(parsed.sessionProgress).toContain('1 /');
    });

    it('should update an existing audit result', async () => {
      const handler = tools['audit_item']?.handler;
      const result = await handler({
        sessionId,
        framework: 'owasp',
        itemId: 'A01', // Updating the same item
        status: 'pass',
        notes: 'Fixed access control'
      });

      expect(result.isError).toBeUndefined();

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.recorded.status).toBe('pass');
      expect(parsed.recorded.notes).toBe('Fixed access control');
      // Progress should remain the same count since it was an update
      expect(parsed.sessionProgress).toContain('1 /');
    });
  });

  describe('generate_report tool', () => {
    const sessionId = 'report-session-123';

    beforeEach(async () => {
      // Setup a session with some results
      const handler = tools['audit_item']?.handler;
      await handler({ sessionId, framework: 'owasp', itemId: 'A01', status: 'pass' });
      await handler({ sessionId, framework: 'owasp', itemId: 'A02', status: 'fail', notes: 'Bad crypto' });
      await handler({ sessionId, framework: 'owasp', itemId: 'A03', status: 'skip' });
    });

    it('should return error for unknown session', async () => {
      const handler = tools['generate_report']?.handler;
      const result = await handler({ sessionId: 'unknown', format: 'json' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Session 'unknown' not found.");
    });

    it('should generate json report', async () => {
      const handler = tools['generate_report']?.handler;
      const result = await handler({ sessionId, format: 'json' });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.session).toBe(sessionId);
      expect(parsed.framework).toBe('OWASP Top 10');
      expect(parsed.summary.passed).toBe(1);
      expect(parsed.summary.failed).toBe(1);
      expect(parsed.summary.skipped).toBe(1);
      expect(parsed.score).toBe('33%'); // 1/3 passed
    });

    it('should generate markdown report', async () => {
      const handler = tools['generate_report']?.handler;
      const result = await handler({ sessionId, format: 'markdown' });

      const text = result.content[0].text;
      expect(text).toContain('# 🔒 Security Audit Report');
      expect(text).toContain('OWASP Top 10');
      expect(text).toContain('Score:** 33%');
      expect(text).toContain('## 🚨 Critical Findings');
      expect(text).toContain('Bad crypto');
    });

    it('should generate html report', async () => {
      const handler = tools['generate_report']?.handler;
      const result = await handler({ sessionId, format: 'html' });

      const text = result.content[0].text;
      expect(text).toContain('<!DOCTYPE html>');
      expect(text).toContain('<h1>🔒 Security Audit Report</h1>');
      expect(text).toContain('<div class="score">33%</div>');
      expect(text).toContain('Bad crypto');
    });
  });

  describe('get_risk_summary tool', () => {
    it('should return a breakdown of risks for a framework', async () => {
      const handler = tools['get_risk_summary']?.handler;
      const result = await handler({ framework: 'owasp' });

      expect(result.content[0].type).toBe('text');
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.framework).toBe('OWASP Top 10');
      expect(parsed.riskBreakdown).toBeDefined();
      expect(parsed.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
      expect(parsed.riskBreakdown.HIGH).toBeInstanceOf(Array);

      // OWASP has 3 CRITICALs (A01, A02, A03)
      expect(parsed.riskBreakdown.CRITICAL.length).toBe(3);
    });
  });

  describe('search_controls tool', () => {
    it('should search controls across all frameworks', async () => {
      const handler = tools['search_controls']?.handler;
      const result = await handler({ query: 'encrypt', framework: 'all' });

      expect(result.content[0].type).toBe('text');
      const parsed = JSON.parse(result.content[0].text);

      expect(parsed.query).toBe('encrypt');
      expect(parsed.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(parsed.results).length).toBeGreaterThan(0);
    });

    it('should search controls in a specific framework', async () => {
      const handler = tools['search_controls']?.handler;
      const result = await handler({ query: 'injection', framework: 'owasp' });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.results['OWASP Top 10']).toBeDefined();
      expect(parsed.results['OWASP Top 10'][0].id).toBe('A03'); // Injection
    });

    it('should return empty results for no matches', async () => {
      const handler = tools['search_controls']?.handler;
      const result = await handler({ query: 'nonexistentterm12345', framework: 'all' });

      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.totalMatches).toBe(0);
      expect(Object.keys(parsed.results).length).toBe(0);
    });
  });
});
