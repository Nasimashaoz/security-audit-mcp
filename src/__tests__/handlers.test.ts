import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup
} from '../handlers.js';
import { clearSessions, sessions } from '../state.js';
import { FRAMEWORKS } from '../frameworks.js';

describe('Handlers', () => {
  beforeEach(() => {
    clearSessions();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2023-01-01T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  describe('handleListFrameworks', () => {
    it('should return a list of frameworks', async () => {
      const response = await handleListFrameworks();
      expect(response.content[0].type).toBe('text');
      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks.find((f: any) => f.id === 'owasp')).toBeDefined();
    });
  });

  describe('handleGetFramework', () => {
    it('should return a specific framework', async () => {
      const response = await handleGetFramework({ framework: 'nist' });
      expect(response.content[0].type).toBe('text');
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe('NIST SP 800-53');
    });

    it('should return error for unknown framework', async () => {
      const response = await handleGetFramework({ framework: 'unknown' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe('handleAuditItem', () => {
    it('should record an audit item successfully', async () => {
      const response = await handleAuditItem({
        sessionId: 'test-session-1',
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Needs fix'
      });
      expect(response.content[0].type).toBe('text');
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('fail');

      const session = sessions.get('test-session-1');
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
    });

    it('should update an existing audit item', async () => {
      await handleAuditItem({ sessionId: 's1', framework: 'owasp', itemId: 'A01', status: 'fail' });
      await handleAuditItem({ sessionId: 's1', framework: 'owasp', itemId: 'A01', status: 'pass' });
      const session = sessions.get('s1');
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].status).toBe('pass');
    });

    it('should return error for unknown item', async () => {
      const response = await handleAuditItem({
        sessionId: 's2',
        framework: 'owasp',
        itemId: 'unknown-item',
        status: 'pass'
      });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found in owasp");
    });
  });

  describe('handleGenerateReport', () => {
    beforeEach(async () => {
      await handleAuditItem({ sessionId: 's1', framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'Critical fix' });
      await handleAuditItem({ sessionId: 's1', framework: 'owasp', itemId: 'A02', status: 'pass' });
    });

    it('should generate markdown report by default', async () => {
      const response = await handleGenerateReport({ sessionId: 's1' });
      expect(response.content[0].type).toBe('text');
      expect(response.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(response.content[0].text).toContain('OWASP Top 10');
      expect(response.content[0].text).toContain('A01');
      expect(response.content[0].text).toContain('Critical fix');
    });

    it('should generate json report', async () => {
      const response = await handleGenerateReport({ sessionId: 's1', format: 'json' });
      const data = JSON.parse(response.content[0].text);
      expect(data.score).toBe('50%');
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.criticalFindings.length).toBe(1);
    });

    it('should generate html report', async () => {
      const response = await handleGenerateReport({ sessionId: 's1', format: 'html' });
      expect(response.content[0].text).toContain('<!DOCTYPE html>');
      expect(response.content[0].text).toContain('OWASP Top 10');
    });

    it('should return error for unknown session', async () => {
      const response = await handleGenerateReport({ sessionId: 'unknown' });
      expect(response.isError).toBe(true);
    });
  });

  describe('handleGetRiskSummary', () => {
    it('should return risk breakdown', async () => {
      const response = await handleGetRiskSummary({ framework: 'owasp' });
      const data = JSON.parse(response.content[0].text);
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe('handleSearchControls', () => {
    it('should find matching controls', async () => {
      const response = await handleSearchControls({ query: 'cryptographic' });
      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results['OWASP Top 10']).toBeDefined();
    });

    it('should search within a specific framework', async () => {
      const response = await handleSearchControls({ query: 'access', framework: 'nist' });
      const data = JSON.parse(response.content[0].text);
      expect(data.results['NIST SP 800-53']).toBeDefined();
      expect(data.results['OWASP Top 10']).toBeUndefined();
    });
  });

  describe('handleCveLookup', () => {
    it('should return invalid format error', async () => {
      const response = await handleCveLookup({ cveId: 'invalid-cve' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('Invalid CVE ID format');
    });

    it('should successfully fetch CVE data', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id: 'CVE-2021-44228', description: 'Log4j vulnerability' })
      });
      vi.stubGlobal('fetch', mockFetch);

      const response = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(response.content[0].type).toBe('text');
      const data = JSON.parse(response.content[0].text);
      expect(data.id).toBe('CVE-2021-44228');
      expect(mockFetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
    });

    it('should handle API fetch error (not ok)', async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: false });
      vi.stubGlobal('fetch', mockFetch);

      const response = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('not found or API error');
    });

    it('should handle network error (throws exception)', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
      vi.stubGlobal('fetch', mockFetch);

      const response = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('Network error');
    });
  });
});
