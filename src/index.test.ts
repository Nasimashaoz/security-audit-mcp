import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

// Mock transport since we can't connect stdio in tests
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      async start() {}
      async close() {}
    }
  };
});

describe('security-audit-mcp tools', () => {
  const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00.000Z'));
    global.fetch = vi.fn() as any;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.resetAllMocks();
  });

  it('should have tools registered', () => {
      expect(toolsMap).toBeDefined();
  });

  describe('list_frameworks', () => {
    it('should list all available frameworks', async () => {
      const handler = toolsMap['list_frameworks'].handler;
      const result = await handler({});
      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks.some((fw: any) => fw.id === 'owasp')).toBe(true);
      expect(data.frameworks.some((fw: any) => fw.id === 'pcidss')).toBe(true);
    });
  });

  describe('get_framework', () => {
    it('should return checklist for a specific framework', async () => {
      const handler = toolsMap['get_framework'].handler;
      const result = await handler({ framework: 'owasp' });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe('OWASP Top 10');
      expect(data.items.length).toBeGreaterThan(0);
    });

    it('should handle invalid framework gracefully (though zod should catch this, testing fallback)', async () => {
      const handler = toolsMap['get_framework'].handler;
      const result = await handler({ framework: 'invalid_framework' as any });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });
  });

  describe('get_risk_summary', () => {
    it('should breakdown risks by severity', async () => {
      const handler = toolsMap['get_risk_summary'].handler;
      const result = await handler({ framework: 'owasp' });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.riskBreakdown).toBeDefined();
      expect(data.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
      expect(data.riskBreakdown.HIGH).toBeInstanceOf(Array);
    });
  });

  describe('audit_item and generate_report', () => {
    const sessionId = 'test-session-123';

    it('should audit an item', async () => {
      const handler = toolsMap['audit_item'].handler;
      const result = await handler({
        sessionId,
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Failed access control test',
      });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('fail');
      expect(data.recorded.notes).toBe('Failed access control test');
    });

    it('should overwrite existing audit item', async () => {
      const handler = toolsMap['audit_item'].handler;
      const result = await handler({
        sessionId,
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass',
        notes: 'Fixed access control',
      });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.status).toBe('pass');
      expect(data.recorded.notes).toBe('Fixed access control');
    });

    it('should return error for invalid item', async () => {
      const handler = toolsMap['audit_item'].handler;
      const result = await handler({
        sessionId,
        framework: 'owasp',
        itemId: 'INVALID_ID',
        status: 'pass',
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });

    it('should generate JSON report', async () => {
      const handler = toolsMap['generate_report'].handler;
      const result = await handler({ sessionId, format: 'json' });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe(sessionId);
      expect(data.summary.passed).toBe(1);
    });

    it('should generate markdown report', async () => {
      const handler = toolsMap['generate_report'].handler;
      // Note: format is optional in schema with default, but we're calling handler directly
      // so we should provide it to bypass zod defaults, or test that it handles if missing if we handled defaults in code (we didn't, zod does it)
      // Actually we'll pass 'markdown' explicitly.
      const result = await handler({ sessionId, format: 'markdown' });
      expect(result.content).toBeDefined();
      expect(result.content[0].text).toContain('Security Audit Report');
      expect(result.content[0].text).toContain('A01');
    });

    it('should generate HTML report', async () => {
      const handler = toolsMap['generate_report'].handler;
      const result = await handler({ sessionId, format: 'html' });
      expect(result.content).toBeDefined();
      expect(result.content[0].text).toContain('<!DOCTYPE html>');
      expect(result.content[0].text).toContain('A01');
    });

    it('should return error for invalid session', async () => {
      const handler = toolsMap['generate_report'].handler;
      const result = await handler({ sessionId: 'nonexistent', format: 'json' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found');
    });
  });

  describe('search_controls', () => {
    it('should search controls across all frameworks', async () => {
      const handler = toolsMap['search_controls'].handler;
      const result = await handler({ query: 'injection', framework: 'all' });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results['OWASP Top 10']).toBeDefined();
    });

    it('should search controls within a specific framework', async () => {
      const handler = toolsMap['search_controls'].handler;
      const result = await handler({ query: 'access', framework: 'nist' });
      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.results['NIST SP 800-53']).toBeDefined();
      expect(data.results['OWASP Top 10']).toBeUndefined();
    });
  });

  describe('cve_lookup', () => {
    it('should successfully lookup a CVE', async () => {
      const mockCveData = {
        cveMetadata: {
          cveId: "CVE-2021-44228",
          state: "PUBLISHED",
          assignerShortName: "apache",
          datePublished: "2021-12-10T00:00:00Z"
        },
        containers: {
          cna: {
            descriptions: [{ value: "Log4j vulnerability" }],
            metrics: [{
              cvssV3_1: {
                baseScore: 10.0,
                baseSeverity: "CRITICAL",
                vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
              }
            }]
          }
        }
      };

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockCveData
      });

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-2021-44228' });

      expect(result.content).toBeDefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.cveId).toBe("CVE-2021-44228");
      expect(data.severity).toContain("Score: 10");
      expect(data.description).toBe("Log4j vulnerability");
      expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
    });

    it('should handle CVE not found', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-UNKNOWN' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it('should handle API failure', async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 500
      });

      const handler = toolsMap['cve_lookup'].handler;
      const result = await handler({ cveId: 'CVE-2021-44228' });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Failed to lookup CVE");
    });
  });
});
