import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  handleListFrameworks,
  handleGetFramework,
  handleAuditItem,
  handleGenerateReport,
  handleGetRiskSummary,
  handleSearchControls,
  handleCveLookup,
  clearSessions,
  sessions
} from './handlers.js';
import { FRAMEWORKS } from './frameworks.js';

describe('Tool Handlers', () => {
  beforeEach(() => {
    clearSessions();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-01-01T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('handleListFrameworks', () => {
    it('returns a list of available frameworks', async () => {
      const result = await handleListFrameworks();
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.frameworks.length).toBeGreaterThan(0);
      expect(data.frameworks[0]).toHaveProperty('id');
      expect(data.frameworks[0]).toHaveProperty('name');
    });
  });

  describe('handleGetFramework', () => {
    it('returns the framework checklist if found', async () => {
      const result = await handleGetFramework({ framework: 'owasp' });
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.name).toBe('OWASP Top 10');
      expect(data.items.length).toBeGreaterThan(0);
    });

    it('returns an error if framework is not found', async () => {
      const result = await handleGetFramework({ framework: 'unknown' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Framework 'unknown' not found.");
    });
  });

  describe('handleAuditItem', () => {
    it('records a new audit item', async () => {
      const result = await handleAuditItem({
        sessionId: 'session-1',
        framework: 'owasp',
        itemId: 'A01',
        status: 'pass',
        notes: 'Looks good'
      });
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.recorded.itemId).toBe('A01');
      expect(data.recorded.status).toBe('pass');
      expect(sessions.get('session-1')?.results.length).toBe(1);
    });

    it('updates an existing audit item', async () => {
      await handleAuditItem({ sessionId: 'session-1', framework: 'owasp', itemId: 'A01', status: 'pass' });
      await handleAuditItem({ sessionId: 'session-1', framework: 'owasp', itemId: 'A01', status: 'fail' });
      const session = sessions.get('session-1');
      expect(session?.results.length).toBe(1);
      expect(session?.results[0].status).toBe('fail');
    });

    it('returns error if item not found', async () => {
       const result = await handleAuditItem({
        sessionId: 'session-1',
        framework: 'owasp',
        itemId: 'invalid-id',
        status: 'pass'
      });
      expect(result.isError).toBe(true);
    });
  });

  describe('handleGenerateReport', () => {
    it('generates a json report', async () => {
      await handleAuditItem({ sessionId: 'session-1', framework: 'owasp', itemId: 'A01', status: 'pass' });
      const result = await handleGenerateReport({ sessionId: 'session-1', format: 'json' });
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.session).toBe('session-1');
      expect(data.summary.passed).toBe(1);
    });

    it('generates a markdown report', async () => {
      await handleAuditItem({ sessionId: 'session-1', framework: 'owasp', itemId: 'A01', status: 'pass' });
      const result = await handleGenerateReport({ sessionId: 'session-1', format: 'markdown' });
      expect(result.content[0].text).toContain('# 🔒 Security Audit Report');
      expect(result.content[0].text).toContain('A01');
    });

    it('generates an html report', async () => {
      await handleAuditItem({ sessionId: 'session-1', framework: 'owasp', itemId: 'A01', status: 'pass' });
      const result = await handleGenerateReport({ sessionId: 'session-1', format: 'html' });
      expect(result.content[0].text).toContain('<!DOCTYPE html>');
      expect(result.content[0].text).toContain('A01');
    });

    it('returns error if session not found', async () => {
      const result = await handleGenerateReport({ sessionId: 'unknown', format: 'json' });
      expect(result.isError).toBe(true);
    });
  });

  describe('handleGetRiskSummary', () => {
    it('returns risk summary for a framework', async () => {
      const result = await handleGetRiskSummary({ framework: 'owasp' });
      const data = JSON.parse(result.content[0].text);
      expect(data.framework).toBe('OWASP Top 10');
      expect(data.riskBreakdown).toHaveProperty('CRITICAL');
      expect(data.riskBreakdown.CRITICAL.length).toBeGreaterThan(0);
    });
  });

  describe('handleSearchControls', () => {
    it('searches across all frameworks', async () => {
      const result = await handleSearchControls({ query: 'access', framework: 'all' });
      const data = JSON.parse(result.content[0].text);
      expect(data.totalMatches).toBeGreaterThan(0);
      expect(data.results['OWASP Top 10']).toBeDefined();
    });

    it('searches within a specific framework', async () => {
      const result = await handleSearchControls({ query: 'access', framework: 'owasp' });
      const data = JSON.parse(result.content[0].text);
      expect(data.results['NIST SP 800-53']).toBeUndefined();
    });
  });

  describe('handleCveLookup', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('fetches and returns CVE data successfully', async () => {
      const mockResponse = { id: 'CVE-2021-44228', description: 'Log4j vulnerability' };
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(result.content[0].type).toBe('text');
      const data = JSON.parse(result.content[0].text);
      expect(data.id).toBe('CVE-2021-44228');
      expect(mockFetch).toHaveBeenCalledWith('https://cveawg.mitre.org/api/cve/CVE-2021-44228');
    });

    it('handles 404 not found', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await handleCveLookup({ cveId: 'CVE-UNKNOWN' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("CVE 'CVE-UNKNOWN' not found");
    });

    it('handles other fetch errors', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error'
      });
      vi.stubGlobal('fetch', mockFetch);

      const result = await handleCveLookup({ cveId: 'CVE-2021-44228' });
      expect(result.isError).toBe(true);
      expect(result.content[0].text).toContain("Error fetching CVE 'CVE-2021-44228': Internal Server Error");
    });

    it('catches and handles exceptions', async () => {
       const mockFetch = vi.fn().mockRejectedValue(new Error("Network Failure"));
       vi.stubGlobal('fetch', mockFetch);
       const result = await handleCveLookup({ cveId: 'CVE-2021-44228' });
       expect(result.isError).toBe(true);
       expect(result.content[0].text).toContain("Failed to look up CVE 'CVE-2021-44228': Network Failure");
    });
  });
});
