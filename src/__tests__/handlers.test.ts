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
import { clearSessions, setSession } from '../state.js';

describe('Tool Handlers', () => {
  beforeEach(() => {
    clearSessions();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  describe('handleListFrameworks', () => {
    it('returns a list of available frameworks', async () => {
      const result = await handleListFrameworks();
      expect(result.content[0].type).toBe('text');

      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks).toBeInstanceOf(Array);
      expect(data.frameworks.some((fw: any) => fw.id === 'owasp')).toBe(true);
      expect(data.frameworks.some((fw: any) => fw.id === 'nist')).toBe(true);
    });
  });

  describe('handleGetFramework', () => {
    it('returns framework details when found', async () => {
      const result = await handleGetFramework({ framework: 'owasp' });
      expect(result.isError).toBeUndefined();

      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe('OWASP Top 10');
      expect(data.items).toBeInstanceOf(Array);
    });

    it('returns an error if framework is not found', async () => {
      const result = await handleGetFramework({ framework: 'invalid_fw' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("not found");
    });
  });

  describe('handleAuditItem', () => {
    it('records a new audit result and creates session if missing', async () => {
      const result = await handleAuditItem({
        sessionId: 'test-session',
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Needs fix'
      });

      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('fail');
      expect(data.recorded.notes).toBe('Needs fix');
      expect(data.sessionProgress).toContain('1 /');
    });

    it('updates existing result in an active session', async () => {
      await handleAuditItem({
        sessionId: 'test-session',
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass'
      });

      const result2 = await handleAuditItem({
        sessionId: 'test-session',
        framework: 'owasp',
        itemId: 'A01',
        status: 'fail',
        notes: 'Failed again'
      });

      const data = JSON.parse(result2.content[0].text);
      expect(data.recorded.status).toBe('fail');
      expect(data.recorded.notes).toBe('Failed again');
      expect(data.sessionProgress).toContain('1 /'); // Still 1 item audited
    });

    it('returns error if framework does not exist', async () => {
      const result = await handleAuditItem({
        sessionId: 's',
        framework: 'bad',
        itemId: 'A01',
        status: 'pass'
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('Framework \'bad\' not found');
    });

    it('returns error if item does not exist in framework', async () => {
      const result = await handleAuditItem({
        sessionId: 's',
        framework: 'owasp',
        itemId: 'INVALID_ID',
        status: 'pass'
      });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain('not found in owasp');
    });
  });

  describe('handleGenerateReport', () => {
    it('generates a JSON report for an existing session', async () => {
      await handleAuditItem({ sessionId: 'rep', framework: 'owasp', itemId: 'A01', status: 'pass' });
      await handleAuditItem({ sessionId: 'rep', framework: 'owasp', itemId: 'A02', status: 'fail' });

      const result = await handleGenerateReport({ sessionId: 'rep', format: 'json' });
      expect(result.isError).toBeUndefined();

      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe('rep');
      expect(data.summary.passed).toBe(1);
      expect(data.summary.failed).toBe(1);
      expect(data.score).toBe('50%');
      expect(data.generatedAt).toBe('2024-01-01T00:00:00.000Z');
    });

    it('generates a Markdown report', async () => {
      await handleAuditItem({ sessionId: 'rep-md', framework: 'owasp', itemId: 'A01', status: 'fail', notes: 'Urgent' });
      const result = await handleGenerateReport({ sessionId: 'rep-md', format: 'markdown' });

      expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(result.content[0].text).toContain('🚨 Critical Findings');
      expect(result.content[0].text).toContain('**A01**');
    });

    it('generates an HTML report', async () => {
      await handleAuditItem({ sessionId: 'rep-ht', framework: 'owasp', itemId: 'A01', status: 'skip' });
      const result = await handleGenerateReport({ sessionId: 'rep-ht', format: 'html' });

      expect(result.content[0].text).toContain('<!DOCTYPE html>');
      expect(result.content[0].text).toContain('Security Audit Report');
    });

    it('returns error for non-existent session', async () => {
      const result = await handleGenerateReport({ sessionId: 'missing', format: 'json' });
      expect(result.isError).toBe(true);
    });

    it('calculates score correctly for 0 items', async () => {
        setSession('empty-session', { id: 'empty-session', framework: 'owasp', results: [], startedAt: '' });
        const result = await handleGenerateReport({ sessionId: 'empty-session', format: 'json' });
        const data = JSON.parse(result.content[0].text);
        expect(data.score).toBe('0%');
    });
  });

  describe('handleGetRiskSummary', () => {
    it('returns a risk breakdown for a framework', async () => {
      const result = await handleGetRiskSummary({ framework: 'owasp' });
      expect(result.isError).toBeUndefined();
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
      expect(data.riskBreakdown.HIGH.length).toBeGreaterThan(0);
    });

    it('returns error for missing framework', async () => {
      const result = await handleGetRiskSummary({ framework: 'invalid' });
      expect(result.isError).toBe(true);
    });
  });

  describe('handleSearchControls', () => {
    it('searches for keywords in all frameworks by default', async () => {
      const result = await handleSearchControls({ query: 'access', framework: 'all' });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(Object.keys(data.results).length).toBeGreaterThan(0);
    });

    it('searches in a specific framework', async () => {
      const result = await handleSearchControls({ query: 'injection', framework: 'owasp' });
      const data = JSON.parse(result.content[0].text);
      expect(data.results['OWASP Top 10']).toBeDefined();
      expect(data.results['NIST SP 800-53']).toBeUndefined();
    });
  });

  describe('handleCveLookup', () => {
    it('fetches CVE details correctly', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ id: 'CVE-2021-44228', description: 'Log4Shell' })
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(mockFetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');

      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe('CVE-2021-44228');
    });

    it('handles 404 not found correctly', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await handleCveLookup({ cveId: 'cve-missing' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("CVE 'cve-missing' not found");
    });

    it('handles generic HTTP errors correctly', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await handleCveLookup({ cveId: 'cve-error' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Status: 500");
    });

    it('handles network or fetch exceptions', async () => {
      const mockFetch = vi.fn().mockRejectedValue(new Error('Network disconnected'));
      vi.stubGlobal('fetch', mockFetch);

      const result = await handleCveLookup({ cveId: 'cve-error' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Network disconnected");
    });
  });
});
