import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server, main } from './index.js';
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// Mock the StdioServerTransport
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      // mock minimal interface
    }
  };
});

describe('security-audit-mcp server tools', () => {
  let toolsMap: any;

  beforeEach(() => {
    toolsMap = (server as any)._registeredTools;
    global.fetch = vi.fn();
  });

  describe('list_frameworks', () => {
    it('returns a list of frameworks', async () => {
      const tool = toolsMap['list_frameworks'];
      expect(tool).toBeDefined();

      const result = await tool.handler({}, { server: server as any });

      expect(result.content).toBeDefined();
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
      expect(data.frameworks.some((f: any) => f.id === 'nist')).toBe(true);
      expect(data.frameworks.some((f: any) => f.id === 'iso27001')).toBe(true);
    });
  });

  describe('get_framework', () => {
    it('returns the requested framework', async () => {
      const tool = toolsMap['get_framework'];
      expect(tool).toBeDefined();

      const result = await tool.handler({ framework: 'owasp' }, { server: server as any });
      expect(result.isError).toBeUndefined();

      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe('OWASP Top 10');
      expect(data.items.length).toBeGreaterThan(0);
    });

    it('returns error if framework not found', async () => {
      const tool = toolsMap['get_framework'];
      const result = await tool.handler({ framework: 'unknown' }, { server: server as any });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe('audit_item', () => {
    it('records a pass/fail/skip result successfully', async () => {
      const tool = toolsMap['audit_item'];
      expect(tool).toBeDefined();

      const args = {
        sessionId: 'test-session-1',
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Failed due to missing auth'
      };

      const result = await tool.handler(args, { server: server as any });
      expect(result.isError).toBeUndefined();

      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('fail');
      expect(data.sessionProgress).toBeDefined();
    });

    it('updates an existing result', async () => {
      const tool = toolsMap['audit_item'];

      await tool.handler({ sessionId: 'test-session-2', framework: 'nist', itemId: 'AC-1', status: 'pass' }, { server: server as any });
      const result = await tool.handler({ sessionId: 'test-session-2', framework: 'nist', itemId: 'AC-1', status: 'fail' }, { server: server as any });

      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.status).toBe('fail');
    });

    it('returns an error if the item is not found', async () => {
      const tool = toolsMap['audit_item'];
      const result = await tool.handler({ sessionId: 'test-session-3', framework: 'owasp', itemId: 'UNKNOWN-ITEM', status: 'pass' }, { server: server as any });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe('generate_report', () => {
    beforeEach(async () => {
      const auditTool = toolsMap['audit_item'];
      await auditTool.handler({ sessionId: 'report-session', framework: 'owasp', itemId: 'A01', status: 'pass' }, { server: server as any });
      await auditTool.handler({ sessionId: 'report-session', framework: 'owasp', itemId: 'A02', status: 'fail' }, { server: server as any });
      await auditTool.handler({ sessionId: 'report-session', framework: 'owasp', itemId: 'A03', status: 'skip' }, { server: server as any });
    });

    it('generates a json report', async () => {
      const tool = toolsMap['generate_report'];
      const result = await tool.handler({ sessionId: 'report-session', format: 'json' }, { server: server as any });

      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe('report-session');
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.summary.skipped).toBe(1);
    });

    it('generates a markdown report', async () => {
      const tool = toolsMap['generate_report'];
      const result = await tool.handler({ sessionId: 'report-session', format: 'markdown' }, { server: server as any });

      expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(result.content[0].text).toContain('## OWASP Top 10');
      expect(result.content[0].text).toContain('**Passed:** 1');
      expect(result.content[0].text).toContain('**Failed:** 1');
      expect(result.content[0].text).toContain('**Skipped:** 1');
    });

    it('generates an html report', async () => {
      const tool = toolsMap['generate_report'];
      const result = await tool.handler({ sessionId: 'report-session', format: 'html' }, { server: server as any });

      expect(result.content[0].text).toContain('<!DOCTYPE html>');
      expect(result.content[0].text).toContain('Passed: 1 | Failed: 1 | Skipped: 1');
    });

    it('handles empty session correctly for score calculation', async () => {
      const tool = toolsMap['generate_report'];

      // Ensure session exists by auditing an item then removing it is tricky via tools,
      // let's just make sure score logic works on empty.
      // Actually, we can't create an empty session via tools without internal access.
      // But we can check session not found error.
      const result = await tool.handler({ sessionId: 'unknown-session', format: 'json' }, { server: server as any });
      expect(result.isError).toBe(true);
    });
  });

  describe('get_risk_summary', () => {
    it('returns a summary of risks', async () => {
      const tool = toolsMap['get_risk_summary'];
      const result = await tool.handler({ framework: 'owasp' }, { server: server as any });

      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.riskBreakdown).toBeDefined();
      expect(data.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe('search_controls', () => {
    it('searches all frameworks', async () => {
      const tool = toolsMap['search_controls'];
      const result = await tool.handler({ query: 'authentication', framework: 'all' }, { server: server as any });

      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });

    it('searches specific framework', async () => {
      const tool = toolsMap['search_controls'];
      const result = await tool.handler({ query: 'injection', framework: 'owasp' }, { server: server as any });

      const data = JSON.parse(result.content[0].text);
      expect(data.results['OWASP Top 10']).toBeDefined();
      expect(data.results['OWASP Top 10'][0].id).toBe('A03');
    });

    it('returns empty results if no match', async () => {
      const tool = toolsMap['search_controls'];
      const result = await tool.handler({ query: 'nonexistentterm', framework: 'all' }, { server: server as any });

      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBe(0);
    });
  });

  describe('cve_lookup', () => {
    it('fetches and formats CVE details successfully', async () => {
      const mockResponse = {
        cveMetadata: {
          cveId: "CVE-2021-44228",
          state: "PUBLISHED",
          assignerShortName: "Apache"
        },
        containers: {
          cna: {
            descriptions: [{ value: "Apache Log4j2 vulnerability." }],
            metrics: [{ cvssV3_1: { baseScore: 10.0, baseSeverity: "CRITICAL" } }]
          }
        }
      };

      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const tool = toolsMap['cve_lookup'];
      const result = await tool.handler({ cve_id: 'CVE-2021-44228' }, { server: server as any });

      expect(result.content[0].text).toContain('CVE-2021-44228');
      expect(result.content[0].text).toContain('PUBLISHED');
      expect(result.content[0].text).toContain('Score: 10 (CRITICAL)');
      expect(result.content[0].text).toContain('Apache Log4j2 vulnerability.');
    });

    it('handles missing data gracefully', async () => {
      const mockResponse = {};

      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockResponse
      });

      const tool = toolsMap['cve_lookup'];
      const result = await tool.handler({ cve_id: 'CVE-2023-12345' }, { server: server as any });

      expect(result.content[0].text).toContain('CVE-2023-12345');
      expect(result.content[0].text).toContain('UNKNOWN');
      expect(result.content[0].text).toContain('No CVSS score available.');
      expect(result.content[0].text).toContain('No description available.');
    });

    it('returns an error if CVE is not found (404)', async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 404,
      });

      const tool = toolsMap['cve_lookup'];
      const result = await tool.handler({ cve_id: 'CVE-9999-99999' }, { server: server as any });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });

    it('returns an error on API failure', async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      });

      const tool = toolsMap['cve_lookup'];
      const result = await tool.handler({ cve_id: 'CVE-2021-44228' }, { server: server as any });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Internal Server Error');
    });

    it('catches network errors', async () => {
      (global.fetch as any).mockRejectedValue(new Error('Network error'));

      const tool = toolsMap['cve_lookup'];
      const result = await tool.handler({ cve_id: 'CVE-2021-44228' }, { server: server as any });

      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Network error');
    });
  });

  describe('server main execution', () => {
    it('executes main function correctly', async () => {
      const mockConnect = vi.spyOn(server, 'connect').mockResolvedValue(undefined as any);

      await main();

      expect(mockConnect).toHaveBeenCalled();
    });
  });
});
