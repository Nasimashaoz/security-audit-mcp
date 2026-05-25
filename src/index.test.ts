import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

// Mock the StdioServerTransport to avoid starting a real transport layer in tests
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      start() { return Promise.resolve(); }
      close() { return Promise.resolve(); }
    }
  };
});

describe('MCP Server Tools', () => {
  let tools: any;

  beforeEach(() => {
    // Access internal registered tools for testing
    tools = (server as any)._registeredTools;
    // Mock global fetch for CVE lookups
    global.fetch = vi.fn();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should register all necessary tools', () => {
    expect(tools['list_frameworks']).toBeDefined();
    expect(tools['get_framework']).toBeDefined();
    expect(tools['audit_item']).toBeDefined();
    expect(tools['generate_report']).toBeDefined();
    expect(tools['get_risk_summary']).toBeDefined();
    expect(tools['search_controls']).toBeDefined();
    expect(tools['cve_lookup']).toBeDefined();
  });

  it('should list all available frameworks', async () => {
    const handler = tools['list_frameworks'].handler;
    const response = await handler({});
    expect(response.content[0].type).toBe('text');
    const data = JSON.parse(response.content[0].text);
    expect(data.frameworks.some((f: any) => f.id === 'owasp')).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === 'pcidss')).toBe(true);
    expect(data.frameworks.some((f: any) => f.id === 'gdpr')).toBe(true);
  });

  it('should get a specific framework correctly', async () => {
    const handler = tools['get_framework'].handler;
    const response = await handler({ framework: 'owasp' });
    expect(response.isError).toBeUndefined();
    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe('OWASP Top 10');
  });

  it('should handle getting an unknown framework gracefully', async () => {
    const handler = tools['get_framework'].handler;
    const response = await handler({ framework: 'unknown_fw' });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain('not found');
  });

  it('should audit an item properly', async () => {
    const handler = tools['audit_item'].handler;
    const sessionId = 'test-session';
    const response = await handler({
      sessionId,
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'Test notes'
    });

    expect(response.isError).toBeUndefined();
    const data = JSON.parse(response.content[0].text);
    expect(data.recorded.itemId).toBe('A01');
    expect(data.recorded.status).toBe('pass');
    expect(data.sessionProgress).toContain('items audited');
  });

  it('should handle auditing an invalid item', async () => {
    const handler = tools['audit_item'].handler;
    const response = await handler({
      sessionId: 'test-session',
      framework: 'owasp',
      itemId: 'UNKNOWN_ITEM',
      status: 'fail',
    });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain('not found');
  });

  it('should generate report successfully', async () => {
    // Audit an item first to populate session
    const auditHandler = tools['audit_item'].handler;
    await auditHandler({
      sessionId: 'report-session',
      framework: 'nist',
      itemId: 'AC-1',
      status: 'pass',
    });

    const reportHandler = tools['generate_report'].handler;
    const jsonResponse = await reportHandler({ sessionId: 'report-session', format: 'json' });
    expect(jsonResponse.isError).toBeUndefined();
    const data = JSON.parse(jsonResponse.content[0].text);
    expect(data.score).toBe('100%');

    const mdResponse = await reportHandler({ sessionId: 'report-session', format: 'markdown' });
    expect(mdResponse.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(mdResponse.content[0].text).toContain('AC-1');
  });

  it('should fail to generate report for unknown session', async () => {
    const reportHandler = tools['generate_report'].handler;
    const response = await reportHandler({ sessionId: 'unknown-session', format: 'json' });
    expect(response.isError).toBe(true);
  });

  it('should lookup cve correctly from API', async () => {
    const mockResponse = {
      containers: { cna: { title: "Test CVE" } }
    };
    (global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => mockResponse
    });

    const handler = tools['cve_lookup'].handler;
    const response = await handler({ cveId: 'CVE-2021-44228' });
    expect(response.isError).toBeUndefined();

    const data = JSON.parse(response.content[0].text);
    expect(data.containers.cna.title).toBe("Test CVE");
    expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
  });

  it('should handle cve not found correctly', async () => {
    (global.fetch as any).mockResolvedValue({
      ok: false,
      status: 404
    });

    const handler = tools['cve_lookup'].handler;
    const response = await handler({ cveId: 'CVE-UNKNOWN' });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain('CVE \'CVE-UNKNOWN\' not found');
  });

  it('should handle search controls across frameworks', async () => {
    const handler = tools['search_controls'].handler;
    const response = await handler({ query: 'encryption', framework: 'all' });
    expect(response.isError).toBeUndefined();
    const data = JSON.parse(response.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
  });

  it('should get risk summary correctly', async () => {
    const handler = tools['get_risk_summary'].handler;
    const response = await handler({ framework: 'iso27001' });
    expect(response.isError).toBeUndefined();
    const data = JSON.parse(response.content[0].text);
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });
});
