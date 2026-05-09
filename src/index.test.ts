import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { server } from './index.js';
import { FRAMEWORKS } from './frameworks.js';
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// Mock the stdio transport since we're testing the server handlers directly
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        onmessage: vi.fn(),
        onclose: vi.fn(),
        onerror: vi.fn(),
        send: vi.fn(),
        close: vi.fn(),
        start: vi.fn(),
      };
    })
  };
});

describe('security-audit-mcp tools', () => {
  const tools = (server as any)._registeredTools || (server as any).tools;

  if (!tools) {
    throw new Error('Could not access registered tools on server instance');
  }

  // Create a helper to easily invoke a tool by name
  const invokeTool = async (name: string, args: any) => {
    // If it's a map we can use .get, otherwise it's probably an object/record
    const tool = tools instanceof Map ? tools.get(name) : tools[name];
    if (!tool || !tool.handler) {
      throw new Error(`Tool ${name} not found or missing handler`);
    }
    return tool.handler(args);
  };

  it('should list all frameworks via list_frameworks', async () => {
    const response = await invokeTool('list_frameworks', {});
    expect(response.content[0].type).toBe('text');

    const data = JSON.parse(response.content[0].text);
    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.length).toBe(Object.keys(FRAMEWORKS).length);

    const fwNames = data.frameworks.map((f: any) => f.id);
    expect(fwNames).toContain('owasp');
    expect(fwNames).toContain('gdpr');
    expect(fwNames).toContain('pcidss');
  });

  it('should get a specific framework via get_framework', async () => {
    const response = await invokeTool('get_framework', { framework: 'nist' });
    expect(response.content[0].type).toBe('text');

    const data = JSON.parse(response.content[0].text);
    expect(data.name).toBe('NIST SP 800-53');
    expect(data.items.length).toBeGreaterThan(0);
  });

  it('should handle getting an invalid framework (should not reach here due to Zod, but testing logic)', async () => {
    // In a real execution, zod would throw before the handler is called
    // We mock a direct handler call to test the internal check
    const response = await invokeTool('get_framework', { framework: 'nonexistent' });
    expect(response.isError).toBe(true);
    expect(response.content[0].text).toContain("not found");
  });

  describe('audit_item and generate_report', () => {
    const sessionId = 'test-session-123';

    it('should record an audit item successfully', async () => {
      const response = await invokeTool('audit_item', {
        sessionId,
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Failed access control check'
      });

      expect(response.content[0].type).toBe('text');
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.status).toBe('fail');
      expect(data.recorded.notes).toBe('Failed access control check');

      // Update same item
      await invokeTool('audit_item', {
        sessionId,
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass',
        notes: 'Fixed access control'
      });

      const updatedResponse = await invokeTool('generate_report', { sessionId, format: 'json' });
      const report = JSON.parse(updatedResponse.content[0].text);
      expect(report.allResults.length).toBe(1);
      expect(report.allResults[0].status).toBe('pass');
    });

    it('should return error for invalid item id', async () => {
      const response = await invokeTool('audit_item', {
        sessionId,
        framework: 'owasp',
        itemId: 'INVALID-ID',
        status: 'pass'
      });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });

    it('should generate report in JSON format', async () => {
      const response = await invokeTool('generate_report', { sessionId, format: 'json' });
      expect(response.content[0].type).toBe('text');
      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe(sessionId);
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.summary.passed).toBe(1);
    });

    it('should generate report in markdown format', async () => {
      const response = await invokeTool('generate_report', { sessionId, format: 'markdown' });
      expect(response.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(response.content[0].text).toContain('OWASP Top 10');
      expect(response.content[0].text).toContain('| A01 |');
    });

    it('should generate report in html format', async () => {
      const response = await invokeTool('generate_report', { sessionId, format: 'html' });
      expect(response.content[0].text).toContain('<!DOCTYPE html>');
      expect(response.content[0].text).toContain('OWASP Top 10');
      expect(response.content[0].text).toContain('<td>A01</td>');
    });

    it('should handle generate report for invalid session', async () => {
      const response = await invokeTool('generate_report', { sessionId: 'unknown', format: 'json' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  it('should get risk summary', async () => {
    const response = await invokeTool('get_risk_summary', { framework: 'iso27001' });
    expect(response.content[0].type).toBe('text');
    const data = JSON.parse(response.content[0].text);

    expect(data.framework).toBe('ISO 27001');
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    expect(data.riskBreakdown.HIGH).toBeDefined();
  });

  it('should search controls across all frameworks', async () => {
    const response = await invokeTool('search_controls', { query: 'encryption', framework: 'all' });
    expect(response.content[0].type).toBe('text');

    const data = JSON.parse(response.content[0].text);
    expect(data.query).toBe('encryption');
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(data.results).length).toBeGreaterThan(0);
  });

  it('should search controls within a specific framework', async () => {
    const response = await invokeTool('search_controls', { query: 'encrypt', framework: 'owasp' });
    expect(response.content[0].type).toBe('text');

    const data = JSON.parse(response.content[0].text);
    expect(data.query).toBe('encrypt');
    expect(data.results['OWASP Top 10']).toBeDefined();

    // Check that there are no results from other frameworks
    const fwNames = Object.keys(data.results);
    expect(fwNames.length).toBeLessThanOrEqual(1);
    if(fwNames.length === 1) {
      expect(fwNames[0]).toBe('OWASP Top 10');
    }
  });

});
