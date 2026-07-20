import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup
} from './handlers.js';
import type { AuditSession } from './types.js';

describe('Handlers', () => {
  describe('handleListFrameworks', () => {
    it('should return a list of frameworks', async () => {
      const response = await handleListFrameworks();
      expect(response.content[0].type).toBe('text');
      const data = JSON.parse(response.content[0].text);
      expect(data.frameworks).toBeDefined();
      expect(Array.isArray(data.frameworks)).toBe(true);
      expect(data.frameworks.some((fw: any) => fw.id === 'owasp')).toBe(true);
    });
  });

  describe('handleGetFramework', () => {
    it('should return a specific framework', async () => {
      const response = await handleGetFramework({ framework: 'owasp' });
      expect(response.isError).toBeUndefined();
      const data = JSON.parse(response.content[0].text);
      expect(data.name).toBe('OWASP Top 10');
    });

    it('should return an error if framework is not found', async () => {
      const response = await handleGetFramework({ framework: 'nonexistent' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain("not found");
    });
  });

  describe('handleAuditItem', () => {
    let sessions: Map<string, AuditSession>;

    beforeEach(() => {
      sessions = new Map<string, AuditSession>();
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should audit an item correctly', async () => {
      const response = await handleAuditItem({
        sessionId: 'test-session',
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass',
        notes: 'Looks good'
      }, sessions);

      expect(response.isError).toBeUndefined();
      const data = JSON.parse(response.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('pass');
      expect(data.recorded.notes).toBe('Looks good');

      const session = sessions.get('test-session');
      expect(session).toBeDefined();
      expect(session?.results.length).toBe(1);
    });

    it('should return error for invalid item', async () => {
      const response = await handleAuditItem({
        sessionId: 'test-session',
        framework: 'owasp',
        itemId: 'INVALID',
        status: 'pass'
      }, sessions);

      expect(response.isError).toBe(true);
    });
  });

  describe('handleGenerateReport', () => {
    let sessions: Map<string, AuditSession>;

    beforeEach(() => {
      sessions = new Map<string, AuditSession>();
      sessions.set('test-session', {
        id: 'test-session',
        framework: 'owasp',
        startedAt: '2024-01-01T12:00:00Z',
        results: [
          { itemId: 'A01', title: 'Test 1', risk: 'CRITICAL', status: 'fail', notes: 'Bad' },
          { itemId: 'A02', title: 'Test 2', risk: 'HIGH', status: 'pass', notes: 'Good' }
        ]
      });
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2024-01-01T13:00:00Z'));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should generate a JSON report', async () => {
      const response = await handleGenerateReport({ sessionId: 'test-session', format: 'json' }, sessions);
      expect(response.isError).toBeUndefined();
      const data = JSON.parse(response.content[0].text);
      expect(data.session).toBe('test-session');
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
    });

    it('should generate a Markdown report by default', async () => {
      const response = await handleGenerateReport({ sessionId: 'test-session' }, sessions);
      expect(response.isError).toBeUndefined();
      expect(response.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(response.content[0].text).toContain('A01');
    });

    it('should generate an HTML report', async () => {
      const response = await handleGenerateReport({ sessionId: 'test-session', format: 'html' }, sessions);
      expect(response.isError).toBeUndefined();
      expect(response.content[0].text).toContain('<!DOCTYPE html>');
      expect(response.content[0].text).toContain('A01');
    });

    it('should return error for invalid session', async () => {
      const response = await handleGenerateReport({ sessionId: 'invalid' }, sessions);
      expect(response.isError).toBe(true);
    });
  });

  describe('handleGetRiskSummary', () => {
    it('should return risk summary for a framework', async () => {
      const response = await handleGetRiskSummary({ framework: 'owasp' });
      expect(response.isError).toBeUndefined();
      const data = JSON.parse(response.content[0].text);
      expect(data.riskBreakdown).toBeDefined();
      expect(data.riskBreakdown.CRITICAL).toBeDefined();
    });

    it('should return an error if framework is not found', async () => {
        const response = await handleGetRiskSummary({ framework: 'nonexistent' });
        expect(response.isError).toBe(true);
    });
  });

  describe('handleSearchControls', () => {
    it('should search controls across all frameworks', async () => {
      const response = await handleSearchControls({ query: 'injection' });
      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results['OWASP Top 10']).toBeDefined();
    });

    it('should search controls in a specific framework', async () => {
      const response = await handleSearchControls({ query: 'access', framework: 'nist' });
      const data = JSON.parse(response.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      // Wait, let's make sure 'access' is in nist.
      // nist has "AC-1" Access Control Policy, etc. Yes.
      expect(data.results['NIST SP 800-53']).toBeDefined();
      expect(data.results['OWASP Top 10']).toBeUndefined();
    });
  });

  describe('handleCveLookup', () => {
    const originalFetch = global.fetch;

    beforeEach(() => {
      global.fetch = vi.fn() as any;
    });

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it('should handle valid CVE lookups', async () => {
      const mockResponse = { id: 'CVE-2021-44228', description: 'Log4j' };
      (global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });

      const response = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(response.isError).toBeUndefined();
      expect(global.fetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');

      const data = JSON.parse(response.content[0].text);
      expect(data.id).toBe('CVE-2021-44228');
    });

    it('should handle invalid format', async () => {
      const response = await handleCveLookup({ cveId: 'INVALID' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('Invalid CVE ID format');
    });

    it('should handle 404 responses', async () => {
      (global.fetch as any).mockResolvedValue({
        ok: false,
        status: 404
      });

      const response = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('not found');
    });

    it('should handle fetch errors', async () => {
      (global.fetch as any).mockRejectedValue(new Error('Network error'));

      const response = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(response.isError).toBe(true);
      expect(response.content[0].text).toContain('Network error');
    });
  });
});
