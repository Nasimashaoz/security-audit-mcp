import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';

// Mock StdioServerTransport
vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    }
  };
});

describe('security-audit-mcp server', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('should initialize server with correct tools', () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    expect(toolsMap).toBeDefined();
    expect(toolsMap['list_frameworks']).toBeDefined();
    expect(toolsMap['get_framework']).toBeDefined();
    expect(toolsMap['audit_item']).toBeDefined();
    expect(toolsMap['generate_report']).toBeDefined();
    expect(toolsMap['get_risk_summary']).toBeDefined();
    expect(toolsMap['search_controls']).toBeDefined();
    expect(toolsMap['cve_lookup']).toBeDefined();
  });

  it('list_frameworks: should list all frameworks', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['list_frameworks'].handler({});

    expect(response.content[0].type).toBe("text");
    const json = JSON.parse(response.content[0].text);
    expect(json.frameworks).toBeInstanceOf(Array);
    expect(json.frameworks.find((f: any) => f.id === 'owasp')).toBeDefined();
    expect(json.frameworks.find((f: any) => f.id === 'pcidss')).toBeDefined();
  });

  it('get_framework: should return valid framework', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['get_framework'].handler({ framework: 'owasp' });

    expect(response.content[0].type).toBe("text");
    const json = JSON.parse(response.content[0].text);
    expect(json.name).toBe("OWASP Top 10");
  });

  it('get_framework: should return error for invalid framework', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['get_framework'].handler({ framework: 'nonexistent' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it('audit_item: should record results properly', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

    const response = await toolsMap['audit_item'].handler({
      sessionId: 'test-session-123',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'Test issue'
    });

    expect(response.content[0].type).toBe("text");
    const json = JSON.parse(response.content[0].text);
    expect(json.recorded.itemId).toBe('A01');
    expect(json.recorded.status).toBe('fail');

    // Update same item
    const updateResponse = await toolsMap['audit_item'].handler({
      sessionId: 'test-session-123',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass',
      notes: 'Fixed issue'
    });
    const updatedJson = JSON.parse(updateResponse.content[0].text);
    expect(updatedJson.recorded.status).toBe('pass');
  });

  it('audit_item: should return error for invalid item', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['audit_item'].handler({
      sessionId: 'test-session-123',
      framework: 'owasp',
      itemId: 'invalid-id',
      status: 'pass'
    });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it('generate_report: should generate valid JSON report', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

    await toolsMap['audit_item'].handler({
      sessionId: 'test-report-json',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'A critical fail'
    });

    const response = await toolsMap['generate_report'].handler({
      sessionId: 'test-report-json',
      format: 'json'
    });

    expect(response.content[0].type).toBe("text");
    const json = JSON.parse(response.content[0].text);
    expect(json.score).toBe("0%");
    expect(json.summary.failed).toBe(1);
    expect(json.criticalFindings.length).toBe(1);
  });

  it('generate_report: should generate valid Markdown report', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

    await toolsMap['audit_item'].handler({
      sessionId: 'test-report-md',
      framework: 'owasp',
      itemId: 'A01',
      status: 'fail',
      notes: 'A critical fail'
    });

    const response = await toolsMap['generate_report'].handler({
      sessionId: 'test-report-md',
      format: 'markdown'
    });

    expect(response.content[0].text).toContain("## 🚨 Critical Findings");
    expect(response.content[0].text).toContain("| A01 |");
  });

  it('generate_report: should generate valid HTML report', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;

    await toolsMap['audit_item'].handler({
      sessionId: 'test-report-html',
      framework: 'owasp',
      itemId: 'A01',
      status: 'pass'
    });

    const response = await toolsMap['generate_report'].handler({
      sessionId: 'test-report-html',
      format: 'html'
    });

    expect(response.content[0].text).toContain("<!DOCTYPE html>");
    expect(response.content[0].text).toContain("100%");
  });

  it('generate_report: should return error for invalid session', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['generate_report'].handler({
      sessionId: 'nonexistent-session',
      format: 'json'
    });

    expect(response.isError).toBe(true);
  });

  it('get_risk_summary: should get breakdown', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['get_risk_summary'].handler({
      framework: 'owasp'
    });

    expect(response.content[0].type).toBe("text");
    const json = JSON.parse(response.content[0].text);
    expect(json.riskBreakdown.CRITICAL).toBeInstanceOf(Array);
    expect(json.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it('search_controls: should search across all frameworks', async () => {
    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['search_controls'].handler({
      query: 'access control',
      framework: 'all'
    });

    expect(response.content[0].type).toBe("text");
    const json = JSON.parse(response.content[0].text);
    expect(json.totalMatches).toBeGreaterThan(0);
    expect(json.results['OWASP Top 10']).toBeDefined();
  });

  it('cve_lookup: should return valid CVE info', async () => {
    const mockCveData = { cveMetadata: { cveId: 'CVE-2021-44228' } };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockCveData
    }) as any;

    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['cve_lookup'].handler({ cveId: 'CVE-2021-44228' });

    expect(response.content[0].type).toBe("text");
    const json = JSON.parse(response.content[0].text);
    expect(json.cveMetadata.cveId).toBe('CVE-2021-44228');
  });

  it('cve_lookup: should handle 404 not found', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404
    }) as any;

    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['cve_lookup'].handler({ cveId: 'CVE-INVALID' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  it('cve_lookup: should handle other api errors', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500
    }) as any;

    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['cve_lookup'].handler({ cveId: 'CVE-2021-44228' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("API returned status: 500");
  });

  it('cve_lookup: should handle fetch error', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error')) as any;

    const toolsMap = (server as any)._tools || (server as any)._registeredTools || (server as any).registeredTools;
    const response = await toolsMap['cve_lookup'].handler({ cveId: 'CVE-2021-44228' });

    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("Network error");
  });
});
