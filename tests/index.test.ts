import { describe, it, expect, vi, beforeEach } from 'vitest';
import { server } from "../src/index.js";
import { FRAMEWORKS } from "../src/frameworks.js";

// Mock the stdio transport since we can't connect a real one in tests
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    }
  };
});

describe('security-audit-mcp tools', () => {
  const toolsMap = (server as any)._registeredTools || (server as any)._tools;

  beforeEach(() => {
    // Reset fetch mock before each test
    global.fetch = vi.fn();
  });

  it('should have frameworks available', () => {
    expect(FRAMEWORKS).toBeDefined();
    expect(FRAMEWORKS.owasp).toBeDefined();
    expect(FRAMEWORKS.nist).toBeDefined();
    expect(FRAMEWORKS.iso27001).toBeDefined();
    expect(FRAMEWORKS.pci_dss).toBeDefined();
    expect(FRAMEWORKS.soc2).toBeDefined();
    expect(FRAMEWORKS.hipaa).toBeDefined();
    expect(FRAMEWORKS.cis_v8).toBeDefined();
    expect(FRAMEWORKS.gdpr).toBeDefined();
  });

  it('should have tools registered', () => {
    expect(toolsMap).toBeDefined();
    const toolNames = toolsMap instanceof Map ? Array.from(toolsMap.keys()) : Object.keys(toolsMap);
    expect(toolNames).toContain('list_frameworks');
    expect(toolNames).toContain('get_framework');
    expect(toolNames).toContain('audit_item');
    expect(toolNames).toContain('generate_report');
    expect(toolNames).toContain('get_risk_summary');
    expect(toolNames).toContain('search_controls');
    expect(toolNames).toContain('cve_lookup');
  });

  it('list_frameworks returns correctly', async () => {
    const listFrameworksHandler = toolsMap instanceof Map ? toolsMap.get('list_frameworks') : toolsMap['list_frameworks'];
    const result = await listFrameworksHandler.handler({});
    expect(result.content[0].text).toContain('OWASP Top 10');
  });

  it('get_framework returns correctly', async () => {
    const getFrameworksHandler = toolsMap instanceof Map ? toolsMap.get('get_framework') : toolsMap['get_framework'];
    const result = await getFrameworksHandler.handler({ framework: 'owasp' });
    expect(result.content[0].text).toContain('Broken Access Control');

    const result2 = await getFrameworksHandler.handler({ framework: 'nonexistent' });
    expect(result2.isError).toBe(true);
  });

  it('audit_item works', async () => {
    const auditItemHandler = toolsMap instanceof Map ? toolsMap.get('audit_item') : toolsMap['audit_item'];

    // valid
    const result = await auditItemHandler.handler({ sessionId: 'session1', framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'test note' });
    expect(result.content[0].text).toContain('recorded');

    // update same
    const resultUpdate = await auditItemHandler.handler({ sessionId: 'session1', framework: 'owasp', itemId: 'A01', status: 'pass' });
    expect(resultUpdate.content[0].text).toContain('pass');

    // invalid item
    const resultError = await auditItemHandler.handler({ sessionId: 'session1', framework: 'owasp', itemId: 'INVALID', status: 'fail' });
    expect(resultError.isError).toBe(true);
  });

  it('generate_report works', async () => {
    const generateReportHandler = toolsMap instanceof Map ? toolsMap.get('generate_report') : toolsMap['generate_report'];

    const resMarkdown = await generateReportHandler.handler({ sessionId: 'session1', format: 'markdown' });
    expect(resMarkdown.content[0].text).toContain('Security Audit Report');

    const resJson = await generateReportHandler.handler({ sessionId: 'session1', format: 'json' });
    expect(resJson.content[0].text).toContain('session1');

    const resHtml = await generateReportHandler.handler({ sessionId: 'session1', format: 'html' });
    expect(resHtml.content[0].text).toContain('<!DOCTYPE html>');

    // not found
    const resError = await generateReportHandler.handler({ sessionId: 'invalid', format: 'markdown' });
    expect(resError.isError).toBe(true);
  });

  it('get_risk_summary works', async () => {
    const getRiskSummaryHandler = toolsMap instanceof Map ? toolsMap.get('get_risk_summary') : toolsMap['get_risk_summary'];
    const result = await getRiskSummaryHandler.handler({ framework: 'owasp' });
    expect(result.content[0].text).toContain('CRITICAL');
  });

  it('search_controls works', async () => {
    const searchControlsHandler = toolsMap instanceof Map ? toolsMap.get('search_controls') : toolsMap['search_controls'];
    const resultAll = await searchControlsHandler.handler({ query: 'encryption', framework: 'all' });
    expect(resultAll.content[0].text).toContain('encryption');

    const resultOne = await searchControlsHandler.handler({ query: 'encryption', framework: 'owasp' });
    expect(resultOne.content[0].text).toContain('encryption');
  });

  it('cve_lookup works', async () => {
    const cveLookupHandler = toolsMap instanceof Map ? toolsMap.get('cve_lookup') : toolsMap['cve_lookup'];

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ id: "CVE-2021-44228", description: "Log4Shell" })
    });

    const result = await cveLookupHandler.handler({ cveId: 'CVE-2021-44228' });
    expect(result.content[0].text).toContain('Log4Shell');

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404
    });

    const result404 = await cveLookupHandler.handler({ cveId: 'CVE-1234-5678' });
    expect(result404.isError).toBe(true);
    expect(result404.content[0].text).toContain('not found');

    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500
    });

    const result500 = await cveLookupHandler.handler({ cveId: 'CVE-1234-5678' });
    expect(result500.isError).toBe(true);

    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
    const resultNet = await cveLookupHandler.handler({ cveId: 'CVE-1234-5678' });
    expect(resultNet.isError).toBe(true);
  });
});
