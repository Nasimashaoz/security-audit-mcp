import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup,
  sessions
} from './handlers.js';

describe('Handlers', () => {
  beforeEach(() => {
    sessions.clear();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T12:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('handleListFrameworks should list frameworks correctly', async () => {
    const result = await handleListFrameworks();
    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);
    expect(data.frameworks).toBeDefined();
    expect(data.frameworks.length).toBeGreaterThan(0);
    const names = data.frameworks.map((f: any) => f.name);
    expect(names).toContain('OWASP Top 10');
    expect(names).toContain('NIST SP 800-53');
  });

  it('handleGetFramework should return valid framework details', async () => {
    const result = await handleGetFramework({ framework: 'owasp' });
    expect(result.content[0].type).toBe('text');
    const fw = JSON.parse(result.content[0].text);
    expect(fw.name).toBe('OWASP Top 10');
    expect(fw.items).toBeDefined();
    expect(fw.items[0].id).toBe('A01');
  });

  it('handleGetFramework should return error for unknown framework', async () => {
    const result = await handleGetFramework({ framework: 'unknown' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Framework 'unknown' not found");
  });

  it('handleAuditItem should record audit result correctly', async () => {
    const sessionId = 'test-session';
    const result = await handleAuditItem({ sessionId, framework: 'owasp', itemId: 'A01', status: 'pass', notes: 'All good' });
    expect(result.content[0].type).toBe('text');

    const data = JSON.parse(result.content[0].text);
    expect(data.recorded.itemId).toBe('A01');
    expect(data.recorded.status).toBe('pass');
    expect(data.recorded.notes).toBe('All good');

    const session = sessions.get(sessionId);
    expect(session).toBeDefined();
    expect(session?.results.length).toBe(1);
    expect(session?.startedAt).toBe('2024-01-01T12:00:00.000Z');
  });

  it('handleAuditItem should update existing audit item', async () => {
    const sessionId = 'test-session';
    await handleAuditItem({ sessionId, framework: 'owasp', itemId: 'A01', status: 'pass' });
    const result = await handleAuditItem({ sessionId, framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'Failed now' });

    const data = JSON.parse(result.content[0].text);
    expect(data.recorded.status).toBe('fail');

    const session = sessions.get(sessionId);
    expect(session?.results.length).toBe(1);
  });

  it('handleAuditItem should return error for unknown framework item', async () => {
    const result = await handleAuditItem({ sessionId: 's1', framework: 'owasp', itemId: 'A999', status: 'pass' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("Item 'A999' not found");
  });

  it('handleGenerateReport should generate markdown report', async () => {
    const sessionId = 'test-session';
    await handleAuditItem({ sessionId, framework: 'owasp', itemId: 'A01', status: 'pass' });
    await handleAuditItem({ sessionId, framework: 'owasp', itemId: 'A02', status: 'fail', notes: 'Missing encryption' });

    const result = await handleGenerateReport({ sessionId, format: 'markdown' });
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
    expect(result.content[0].text).toContain('OWASP Top 10');
    expect(result.content[0].text).toContain('Missing encryption');
    expect(result.content[0].text).toContain('## 🚨 Critical Findings');
  });

  it('handleGenerateReport should generate html report', async () => {
    const sessionId = 'test-session';
    await handleAuditItem({ sessionId, framework: 'owasp', itemId: 'A01', status: 'pass' });

    const result = await handleGenerateReport({ sessionId, format: 'html' });
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('<!DOCTYPE html>');
    expect(result.content[0].text).toContain('<h1>🔒 Security Audit Report</h1>');
  });

  it('handleGenerateReport should generate json report', async () => {
    const sessionId = 'test-session';
    await handleAuditItem({ sessionId, framework: 'owasp', itemId: 'A01', status: 'pass' });

    const result = await handleGenerateReport({ sessionId, format: 'json' });
    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);
    expect(data.framework).toBe('OWASP Top 10');
    expect(data.summary.passed).toBe(1);
  });

  it('handleGenerateReport should return error for unknown session', async () => {
    const result = await handleGenerateReport({ sessionId: 'unknown', format: 'json' });
    expect(result.isError).toBe(true);
  });

  it('handleGetRiskSummary should return risk breakdown', async () => {
    const result = await handleGetRiskSummary({ framework: 'owasp' });
    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);
    expect(data.framework).toBe('OWASP Top 10');
    expect(data.riskBreakdown.CRITICAL).toBeDefined();
    expect(data.riskBreakdown.HIGH).toBeDefined();
    expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
  });

  it('handleSearchControls should find controls across all frameworks', async () => {
    const result = await handleSearchControls({ query: 'encryption', framework: 'all' });
    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);
    expect(data.totalMatches).toBeGreaterThan(0);
    expect(Object.keys(data.results).length).toBeGreaterThan(0);
  });

  it('handleSearchControls should search within specific framework', async () => {
    const result = await handleSearchControls({ query: 'authentication', framework: 'owasp' });
    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);
    expect(Object.keys(data.results)).toEqual(['OWASP Top 10']);
  });

  it('handleCveLookup should return CVE data successfully', async () => {
    const mockData = { id: 'CVE-2021-44228', description: 'Log4j vulnerability' };
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockData
    });

    const result = await handleCveLookup({ cveId: 'CVE-2021-44228' });
    expect(result.content[0].type).toBe('text');
    const data = JSON.parse(result.content[0].text);
    expect(data.id).toBe('CVE-2021-44228');
  });

  it('handleCveLookup should handle 404 correctly', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found'
    });

    const result = await handleCveLookup({ cveId: 'CVE-UNKNOWN' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("CVE 'CVE-UNKNOWN' not found.");
  });

  it('handleCveLookup should handle general fetch errors', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network Failure'));

    const result = await handleCveLookup({ cveId: 'CVE-2021-44228' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Network error or failed to parse response: Network Failure');
  });

  it('handleCveLookup should handle non-404 API errors', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error'
    });

    const result = await handleCveLookup({ cveId: 'CVE-2021-44228' });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('Error fetching CVE data: 500 Internal Server Error');
  });
});
