import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from './index.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: class {
    async start() {}
    async close() {}
  }
}));

describe('Security Audit MCP Server Tools', () => {
  let toolsMap: any;

  beforeEach(() => {
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
  });

  it('should list all available frameworks via list_frameworks', async () => {
    const listFrameworksTool = toolsMap['list_frameworks'];
    expect(listFrameworksTool).toBeDefined();

    const response = await listFrameworksTool.handler({});
    expect(response.content[0].type).toBe('text');
    const content = JSON.parse(response.content[0].text);
    expect(content.frameworks).toBeDefined();
    expect(content.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
    expect(content.frameworks.some((f: any) => f.id === 'nist')).toBe(true);
    expect(content.frameworks.some((f: any) => f.id === 'iso27001')).toBe(true);
    expect(content.frameworks.some((f: any) => f.id === 'pci_dss')).toBe(true);
    expect(content.frameworks.some((f: any) => f.id === 'soc2')).toBe(true);
    expect(content.frameworks.some((f: any) => f.id === 'hipaa')).toBe(true);
    expect(content.frameworks.some((f: any) => f.id === 'cis_v8')).toBe(true);
    expect(content.frameworks.some((f: any) => f.id === 'gdpr')).toBe(true);
  });

  it('should return a framework using get_framework', async () => {
    const getFrameworkTool = toolsMap['get_framework'];
    expect(getFrameworkTool).toBeDefined();

    const response = await getFrameworkTool.handler({ framework: 'owasp' });
    expect(response.content[0].type).toBe('text');
    const content = JSON.parse(response.content[0].text);
    expect(content.name).toBe('OWASP Top 10');
    expect(content.items.length).toBeGreaterThan(0);
  });

  it('should handle get_framework with missing framework', async () => {
    const getFrameworkTool = toolsMap['get_framework'];
    const response = await getFrameworkTool.handler({ framework: 'nonexistent' });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Framework 'nonexistent' not found");
  });

  it('should record an audit item and update a session via audit_item', async () => {
    const auditItemTool = toolsMap['audit_item'];
    expect(auditItemTool).toBeDefined();

    const response = await auditItemTool.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Test note'
    });

    expect(response.content[0].type).toBe('text');
    const content = JSON.parse(response.content[0].text);
    expect(content.recorded.itemId).toBe('A01');
    expect(content.recorded.status).toBe('fail');
    expect(content.sessionProgress).toContain('1 / 10 items audited');
  });

  it('should handle audit_item with missing item', async () => {
    const auditItemTool = toolsMap['audit_item'];
    const response = await auditItemTool.handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'NONEXISTENT',
      status: 'pass'
    });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Item 'NONEXISTENT' not found");
  });

  it('should generate a report via generate_report', async () => {
    const generateReportTool = toolsMap['generate_report'];
    expect(generateReportTool).toBeDefined();

    const responseMarkdown = await generateReportTool.handler({
      sessionId: 'test-session',
      format: 'markdown'
    });

    expect(responseMarkdown.content[0].type).toBe('text');
    expect(responseMarkdown.content[0].text).toContain('A01');
    expect(responseMarkdown.content[0].text).toContain('FAIL');

    const responseJson = await generateReportTool.handler({
      sessionId: 'test-session',
      format: 'json'
    });
    const contentJson = JSON.parse(responseJson.content[0].text);
    expect(contentJson.summary.failed).toBe(1);

    const responseHtml = await generateReportTool.handler({
      sessionId: 'test-session',
      format: 'html'
    });
    expect(responseHtml.content[0].text).toContain('<!DOCTYPE html>');
  });

  it('should handle generate_report with missing session', async () => {
    const generateReportTool = toolsMap['generate_report'];
    const response = await generateReportTool.handler({
      sessionId: 'nonexistent-session',
      format: 'markdown'
    });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Session 'nonexistent-session' not found");
  });

  it('should return risk summary via get_risk_summary', async () => {
    const getRiskSummaryTool = toolsMap['get_risk_summary'];
    expect(getRiskSummaryTool).toBeDefined();

    const response = await getRiskSummaryTool.handler({ framework: 'owasp' });
    expect(response.content[0].type).toBe('text');
    const content = JSON.parse(response.content[0].text);
    expect(content.riskBreakdown.CRITICAL).toBeDefined();
    expect(content.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it('should search controls via search_controls', async () => {
    const searchControlsTool = toolsMap['search_controls'];
    expect(searchControlsTool).toBeDefined();

    const response = await searchControlsTool.handler({
      query: 'injection',
      framework: 'all'
    });

    expect(response.content[0].type).toBe('text');
    const content = JSON.parse(response.content[0].text);
    expect(content.totalMatches).toBeGreaterThan(0);
    expect(content.results['OWASP Top 10']).toBeDefined();
  });
});

describe('cve_lookup tool', () => {
  let toolsMap: any;

  beforeEach(() => {
    toolsMap = (server as any)._registeredTools || (server as any).registeredTools;
    global.fetch = vi.fn();
  });

  it('should successfully lookup a CVE', async () => {
    const mockCveData = {
      containers: {
        cna: {
          title: "Test CVE",
          descriptions: [{ value: "Test description" }]
        }
      }
    };

    (global.fetch as any).mockResolvedValueOnce({
      ok: true,
      json: async () => mockCveData
    });

    const cveLookupTool = toolsMap['cve_lookup'];
    expect(cveLookupTool).toBeDefined();

    const response = await cveLookupTool.handler({ cveId: 'CVE-2021-44228' });

    expect(response.content[0].type).toBe('text');
    const content = JSON.parse(response.content[0].text);
    expect(content.cve).toEqual(mockCveData);
  });

  it('should handle 404 from MITRE API', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      status: 404
    });

    const cveLookupTool = toolsMap['cve_lookup'];
    const response = await cveLookupTool.handler({ cveId: 'CVE-INVALID' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("CVE 'CVE-INVALID' not found");
  });

  it('should handle other API errors', async () => {
    (global.fetch as any).mockResolvedValueOnce({
      ok: false,
      status: 500
    });

    const cveLookupTool = toolsMap['cve_lookup'];
    const response = await cveLookupTool.handler({ cveId: 'CVE-2021-44228' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("API returned status 500");
  });

  it('should handle fetch throwing an error', async () => {
    (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

    const cveLookupTool = toolsMap['cve_lookup'];
    const response = await cveLookupTool.handler({ cveId: 'CVE-2021-44228' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Error looking up CVE: Network error");
  });
});
