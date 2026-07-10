import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

describe('security-audit-mcp server tools', () => {
  let toolsMap: any;

  beforeEach(() => {
    toolsMap = (server as any)._registeredTools;
  });

  describe('list_frameworks', () => {
    it('should list all available frameworks', async () => {
      const handler = toolsMap['list_frameworks'].handler;
      const result = await handler({});
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks.map((f: any) => f.id)).toContain('owasp');
      expect(data.frameworks.map((f: any) => f.id)).toContain('nist');
      expect(data.frameworks.map((f: any) => f.id)).toContain('iso27001');
    });
  });

  describe('get_framework', () => {
    it('should return framework checklist for valid framework', async () => {
      const handler = toolsMap['get_framework'].handler;
      const result = await handler({ framework: 'owasp' });
      expect(result.isError).toBeUndefined();
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe('OWASP Top 10');
      expect(data.items.length).toBe(10);
    });

    it('should return error for invalid framework', async () => {
      const handler = toolsMap['get_framework'].handler;
      const result = await handler({ framework: 'invalid_fw' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Framework 'invalid_fw' not found");
    });
  });

  describe('get_risk_summary', () => {
    it('should return risk breakdown for a framework', async () => {
      const handler = toolsMap['get_risk_summary'].handler;
      const result = await handler({ framework: 'owasp' });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(data.riskBreakdown.HIGH).toBeDefined();
      expect(data.riskBreakdown.MEDIUM).toBeDefined();
      expect(data.riskBreakdown.LOW).toBeDefined();
    });
  });

  describe('search_controls', () => {
    it('should search for keyword across all frameworks by default', async () => {
      const handler = toolsMap['search_controls'].handler;
      const result = await handler({ query: 'authentication', framework: 'all' });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.query).toBe('authentication');
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });

    it('should search for keyword in specific framework', async () => {
      const handler = toolsMap['search_controls'].handler;
      const result = await handler({ query: 'access', framework: 'owasp' });
      const data = JSON.parse(result.content[0].text);
      expect(data.results['OWASP Top 10']).toBeDefined();
      expect(data.results['NIST SP 800-53']).toBeUndefined();
    });

    it('should handle zero matches gracefully', async () => {
      const handler = toolsMap['search_controls'].handler;
      const result = await handler({ query: 'supercalifragilisticexpialidocious', framework: 'all' });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBe(0);
    });
  });

});

describe('audit_item and generate_report', () => {
  let toolsMap: any;
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    toolsMap = (server as any)._registeredTools;
  });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should record an audit item and generate a JSON report', async () => {
      const auditHandler = toolsMap['audit_item'].handler;
      const reportHandler = toolsMap['generate_report'].handler;

      const sessionId = 'test-session-1';

      // Record a pass
      const auditResult1 = await auditHandler({
        sessionId,
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass',
        notes: 'Looks good',
      });
      expect(auditResult1.isError).toBeUndefined();

      // Record a fail
      const auditResult2 = await auditHandler({
        sessionId,
        framework: 'owasp',
        itemId: 'A02',
        status: 'fail',
        notes: 'Needs encryption',
      });
      expect(auditResult2.isError).toBeUndefined();

      // Generate JSON report
      const reportResult = await reportHandler({ sessionId, format: 'json' });
      expect(reportResult.isError).toBeUndefined();
      const reportData = JSON.parse(reportResult.content[0].text);
      expect(reportData.session).toBe(sessionId);
      expect(reportData.score).toBe('50%');
      expect(reportData.summary.passed).toBe(1);
      expect(reportData.summary.failed).toBe(1);
      expect(reportData.criticalFindings.length).toBe(1);
    });

    it('should generate markdown report', async () => {
      const reportHandler = toolsMap['generate_report'].handler;
      const sessionId = 'test-session-1'; // Re-use session from previous test
      const result = await reportHandler({ sessionId, format: 'markdown' });
      expect(result.isError).toBeUndefined();
      const text = result.content[0].text;
      expect(text).toContain('# 🔒 Security Audit Report');
      expect(text).toContain('A01');
      expect(text).toContain('A02');
    });

    it('should generate html report', async () => {
      const reportHandler = toolsMap['generate_report'].handler;
      const sessionId = 'test-session-1'; // Re-use session from previous test
      const result = await reportHandler({ sessionId, format: 'html' });
      expect(result.isError).toBeUndefined();
      const text = result.content[0].text;
      expect(text).toContain('<!DOCTYPE html>');
      expect(text).toContain('<td>A01</td>');
      expect(text).toContain('<td>A02</td>');
    });

    it('should return error for invalid item in audit_item', async () => {
      const handler = toolsMap['audit_item'].handler;
      const result = await handler({
        sessionId: 'test-session-invalid',
        framework: 'owasp',
        itemId: 'INVALID_ITEM',
        status: 'pass',
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Item 'INVALID_ITEM' not found");
    });

    it('should return error for missing session in generate_report', async () => {
      const handler = toolsMap['generate_report'].handler;
      const result = await handler({ sessionId: 'missing-session', format: 'json' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Session 'missing-session' not found");
    });
  });

describe('cve_lookup', () => {
  let toolsMap: any;
  beforeEach(() => {
    toolsMap = (server as any)._registeredTools;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return CVE details for a valid CVE ID', async () => {
    const handler = toolsMap['cve_lookup'].handler;
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: 'CVE-2021-44228', description: 'Log4j vulnerability' }),
    } as any);

    const result = await handler({ cveId: 'CVE-2021-44228' });
    expect(result.isError).toBeUndefined();
    const data = JSON.parse(result.content[0].text);
    expect(data.id).toBe('CVE-2021-44228');
    expect(data.description).toBe('Log4j vulnerability');
    expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
  });

  it('should return error for non-existent CVE ID', async () => {
    const handler = toolsMap['cve_lookup'].handler;
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    } as any);

    const result = await handler({ cveId: 'CVE-INVALID' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("CVE 'CVE-INVALID' not found.");
  });

  it('should return error for other API errors', async () => {
    const handler = toolsMap['cve_lookup'].handler;
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
    } as any);

    const result = await handler({ cveId: 'CVE-ERROR' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Error fetching CVE data: API returned status 500");
  });

  it('should handle network or parse errors gracefully', async () => {
    const handler = toolsMap['cve_lookup'].handler;
    global.fetch = vi.fn().mockRejectedValue(new Error('Network failure'));

    const result = await handler({ cveId: 'CVE-FAIL' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Error fetching CVE data: Network failure");
  });
});
