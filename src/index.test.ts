import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

// Mock the StdioServerTransport to prevent real stdio connection attempts in tests
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    }
  };
});

describe('security-audit-mcp server tools', () => {
  let toolsMap: any;

  beforeEach(() => {
    // Access internal tools registry for direct handler invocation
    toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
    global.fetch = vi.fn();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('should verify the test scaffold is loaded properly', () => {
    expect(toolsMap).toBeDefined();
    expect(Object.keys(toolsMap).length).toBeGreaterThan(0);
  });

  describe('list_frameworks', () => {
    it('should list all available security frameworks', async () => {
      const handler = toolsMap['list_frameworks'].handler;
      const result = await handler({});
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBeGreaterThan(3); // Should contain more than the original 3

      const owasp = data.frameworks.find((f: any) => f.id === 'owasp');
      expect(owasp).toBeDefined();
      expect(owasp.name).toBe('OWASP Top 10');
    });
  });

  describe('audit_item', () => {
    it('should create session and record audit item correctly', async () => {
      const handler = toolsMap['audit_item'].handler;

      const result = await handler({
        sessionId: 'test-session-1',
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Needs fix'
      });

      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('fail');
      expect(data.recorded.notes).toBe('Needs fix');
      expect(data.sessionProgress).toContain('1 / 10 items audited');
    });

    it('should update existing item result in a session', async () => {
      const handler = toolsMap['audit_item'].handler;

      await handler({
        sessionId: 'test-session-1',
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail'
      });

      const result2 = await handler({
        sessionId: 'test-session-1',
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass',
        notes: 'Fixed'
      });

      const data = JSON.parse(result2.content[0].text);
      expect(data.recorded.status).toBe('pass');
      expect(data.recorded.notes).toBe('Fixed');
      expect(data.sessionProgress).toContain('1 / 10 items audited');
    });

    it('should return error for invalid item ID', async () => {
      const handler = toolsMap['audit_item'].handler;
      const result = await handler({
        sessionId: 'test-session-2',
        framework: 'owasp',
        itemId: 'INVALID-ID',
        status: 'pass'
      });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Item 'INVALID-ID' not found in owasp.");
    });
  });

  describe('generate_report', () => {
    it('should return error for non-existent session', async () => {
      const handler = toolsMap['generate_report'].handler;
      const result = await handler({ sessionId: 'unknown-session', format: 'json' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Session 'unknown-session' not found.");
    });

    it('should generate report in json format', async () => {
      const auditHandler = toolsMap['audit_item'].handler;
      await auditHandler({ sessionId: 'rep-session', framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'critical issue' });
      await auditHandler({ sessionId: 'rep-session', framework: 'owasp', itemId: 'A02', status: 'pass' });

      const reportHandler = toolsMap['generate_report'].handler;
      const result = await reportHandler({ sessionId: 'rep-session', format: 'json' });

      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe('rep-session');
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.criticalFindings.length).toBe(1);
      expect(data.criticalFindings[0].itemId).toBe('A01');
      expect(data.generatedAt).toBe('2024-01-01T12:00:00.000Z');
    });

    it('should generate report in markdown format', async () => {
      const reportHandler = toolsMap['generate_report'].handler;
      const result = await reportHandler({ sessionId: 'rep-session', format: 'markdown' });

      const text = result.content[0].text;
      expect(text).toContain('# 🔒 Security Audit Report');
      expect(text).toContain('## OWASP Top 10');
      expect(text).toContain('**Passed:** 1 | **Failed:** 1');
      expect(text).toContain('## 🚨 Critical Findings');
      expect(text).toContain('**A01**');
    });

    it('should generate report in html format', async () => {
      const reportHandler = toolsMap['generate_report'].handler;
      const result = await reportHandler({ sessionId: 'rep-session', format: 'html' });

      const text = result.content[0].text;
      expect(text).toContain('<!DOCTYPE html>');
      expect(text).toContain('<h1>🔒 Security Audit Report</h1>');
      expect(text).toContain('Passed: 1 | Failed: 1 | Skipped: 0');
      expect(text).toContain('<td>A01</td>');
    });
  });

  describe('get_risk_summary', () => {
    it('should get a risk summary for a framework', async () => {
      const handler = toolsMap['get_risk_summary'].handler;
      const result = await handler({ framework: 'owasp' });

      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.riskBreakdown.CRITICAL.length).toBe(3); // A01, A02, A03 are CRITICAL
      expect(data.riskBreakdown.HIGH.length).toBe(5);
    });
  });

  describe('search_controls', () => {
    it('should search controls across all frameworks', async () => {
      const handler = toolsMap['search_controls'].handler;
      const result = await handler({ query: 'encryption', framework: 'all' });

      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.query).toBe('encryption');
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results['GDPR']).toBeDefined(); // Art-32 explicitly mentions encryption
    });

    it('should search controls in a specific framework', async () => {
      const handler = toolsMap['search_controls'].handler;
      const result = await handler({ query: 'injection', framework: 'owasp' });

      const data = JSON.parse(result.content[0].text);
      expect(data.results['OWASP Top 10']).toBeDefined(); // A03 is Injection
      expect(data.results['NIST SP 800-53']).toBeUndefined(); // Ensure not searching other frameworks
    });
  });

  describe('cve_lookup', () => {
    it('should look up CVE successfully', async () => {
      const mockCveData = {
        cveMetadata: { cveId: 'CVE-2021-44228' },
        containers: { cna: { descriptions: [{ value: 'Log4j vulnerability' }] } }
      };

      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData,
      });

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-2021-44228' });

      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.cveMetadata.cveId).toBe('CVE-2021-44228');
      expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
    });

    it('should handle CVE not found', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-UNKNOWN' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("CVE 'CVE-UNKNOWN' not found.");
    });

    it('should handle API errors', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-2021-44228' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('API returned status 500');
    });

    it('should handle fetch failures', async () => {
      (global.fetch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('Network error'));

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-2021-44228' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Error looking up CVE: Network error');
    });
  });

  describe('get_framework', () => {
    it('should get details for a specific framework', async () => {
      const handler = toolsMap['get_framework'].handler;
      const result = await handler({ framework: 'owasp' });
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe('OWASP Top 10');
      expect(data.items.length).toBe(10);
    });

    it('should handle non-existent framework gracefully', async () => {
      const handler = toolsMap['get_framework'].handler;
      const result = await handler({ framework: 'invalid_fw' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Framework 'invalid_fw' not found");
    });
  });
});
