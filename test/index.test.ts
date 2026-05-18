import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from '../src/index.js';
import { FRAMEWORKS } from '../src/frameworks.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        start: vi.fn(),
        close: vi.fn(),
        send: vi.fn(),
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn()
      };
    })
  };
});

describe('security-audit-mcp server tools', () => {
  const tools = (server as any)._registeredTools;

  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn();
  });

  describe('list_frameworks', () => {
    it('should return all available frameworks', async () => {
      const result = await tools['list_frameworks'].handler({});
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);
      expect(data.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
      expect(data.frameworks.some((f: any) => f.id === 'pcidss')).toBe(true);
    });
  });

  describe('get_framework', () => {
    it('should return the full checklist for a valid framework', async () => {
      const result = await tools['get_framework'].handler({ framework: 'owasp' });
      expect(result.content[0].type).toBe('text');
      expect(result.isError).toBeUndefined();

      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe('OWASP Top 10');
      expect(data.items.length).toBe(10);
    });

    it('should return an error for an invalid framework (should not reach here due to zod, but testing logic)', async () => {
      const result = await tools['get_framework'].handler({ framework: 'invalid' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Framework 'invalid' not found");
    });
  });

  describe('get_risk_summary', () => {
    it('should return a breakdown of risks for a framework', async () => {
      const result = await tools['get_risk_summary'].handler({ framework: 'owasp' });
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(data.riskBreakdown.HIGH).toBeDefined();
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe('audit_item', () => {
    it('should record an audit result and return session progress', async () => {
      const result = await tools['audit_item'].handler({
        sessionId: 'test-session-1',
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Failed access control check'
      });

      expect(result.content[0].type).toBe('text');
      expect(result.isError).toBeUndefined();

      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('fail');
      expect(data.recorded.notes).toBe('Failed access control check');
      expect(data.sessionProgress).toContain('1 / 10 items audited');
    });

    it('should update an existing audit result', async () => {
      await tools['audit_item'].handler({
        sessionId: 'test-session-2',
        framework: 'nist',
        itemId: 'AC-1',
        status: 'pass'
      });

      const result = await tools['audit_item'].handler({
        sessionId: 'test-session-2',
        framework: 'nist',
        itemId: 'AC-1',
        status: 'fail',
        notes: 'Changed to fail'
      });

      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.status).toBe('fail');
      expect(data.recorded.notes).toBe('Changed to fail');
      expect(data.sessionProgress).toContain('1 / 13 items audited');
    });

    it('should return error if item does not exist', async () => {
      const result = await tools['audit_item'].handler({
        sessionId: 'test-session-3',
        framework: 'owasp',
        itemId: 'INVALID-ITEM',
        status: 'pass'
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Item 'INVALID-ITEM' not found in owasp");
    });
  });

  describe('generate_report', () => {
    beforeEach(async () => {
      // Setup a session with some results
      await tools['audit_item'].handler({ sessionId: 'report-session', framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'Fail 1' });
      await tools['audit_item'].handler({ sessionId: 'report-session', framework: 'owasp', itemId: 'A02', status: 'pass' });
      await tools['audit_item'].handler({ sessionId: 'report-session', framework: 'owasp', itemId: 'A03', status: 'skip' });
    });

    it('should generate a json report', async () => {
      const result = await tools['generate_report'].handler({ sessionId: 'report-session', format: 'json' });
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe('report-session');
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.summary.skipped).toBe(1);
      expect(data.score).toBe('33%'); // 1/3 passed
    });

    it('should generate a markdown report', async () => {
      const result = await tools['generate_report'].handler({ sessionId: 'report-session', format: 'markdown' });
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(result.content[0].text).toContain('## OWASP Top 10');
      expect(result.content[0].text).toContain('**Score:** 33%');
      expect(result.content[0].text).toContain('| A01 |');
    });

    it('should generate an html report', async () => {
      const result = await tools['generate_report'].handler({ sessionId: 'report-session', format: 'html' });
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('<!DOCTYPE html>');
      expect(result.content[0].text).toContain('<h1>🔒 Security Audit Report</h1>');
      expect(result.content[0].text).toContain('<div class="score">33%</div>');
    });

    it('should return error if session not found', async () => {
      const result = await tools['generate_report'].handler({ sessionId: 'invalid-session', format: 'json' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Session 'invalid-session' not found");
    });
  });

  describe('search_controls', () => {
    it('should find controls by keyword across all frameworks', async () => {
      const result = await tools['search_controls'].handler({ query: 'encryption', framework: 'all' });
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.query).toBe('encryption');
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });

    it('should find controls by keyword in a specific framework', async () => {
      const result = await tools['search_controls'].handler({ query: 'encrypted', framework: 'owasp' });
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.results['OWASP Top 10']).toBeDefined();
      // Ensure no other frameworks are returned
      expect(Object.keys(data.results).length).toBe(1);
    });

    it('should handle no matches found', async () => {
      const result = await tools['search_controls'].handler({ query: 'nonexistentkeyword123', framework: 'all' });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBe(0);
      expect(Object.keys(data.results).length).toBe(0);
    });
  });

  describe('cve_lookup', () => {
    it('should return CVE details when API call succeeds', async () => {
      const mockResponse = {
        containers: {
          cna: {
            descriptions: [{ value: "A vulnerability description" }]
          }
        }
      };

      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const result = await tools['cve_lookup'].handler({ cveId: 'CVE-2021-44228' });

      expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.containers.cna.descriptions[0].value).toBe('A vulnerability description');
    });

    it('should handle CVE not found', async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 404
      });

      const result = await tools['cve_lookup'].handler({ cveId: 'CVE-9999-99999' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("CVE 'CVE-9999-99999' not found");
    });

    it('should handle API errors', async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      });

      const result = await tools['cve_lookup'].handler({ cveId: 'CVE-2021-44228' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("MITRE API error: Internal Server Error");
    });

    it('should handle network/fetch failures', async () => {
      (global.fetch as any).mockRejectedValue(new Error('Network offline'));

      const result = await tools['cve_lookup'].handler({ cveId: 'CVE-2021-44228' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to fetch CVE data: Network offline");
    });
  });
});
