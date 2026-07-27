import { describe, it, expect, beforeEach } from 'vitest';
import { getSession, setSession, hasSession, clearSessions } from '../state.js';

describe('State Manager', () => {
  beforeEach(() => {
    clearSessions();
  });

  it('should initially have no sessions', () => {
    expect(hasSession('test-id')).toBe(false);
    expect(getSession('test-id')).toBeUndefined();
  });

  it('should set and get a session correctly', () => {
    const mockSession = {
      id: 'test-id',
      framework: 'owasp',
      startedAt: new Date().toISOString(),
      results: []
    };

    setSession('test-id', mockSession);

    expect(hasSession('test-id')).toBe(true);
    expect(getSession('test-id')).toEqual(mockSession);
  });

  it('should clear all sessions', () => {
    setSession('id1', { id: 'id1', framework: 'owasp', startedAt: '', results: [] });
    setSession('id2', { id: 'id2', framework: 'nist', startedAt: '', results: [] });

    expect(hasSession('id1')).toBe(true);
    expect(hasSession('id2')).toBe(true);

    clearSessions();

    expect(hasSession('id1')).toBe(false);
    expect(hasSession('id2')).toBe(false);
  });
});
