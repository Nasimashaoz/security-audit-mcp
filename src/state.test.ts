import { describe, it, expect, beforeEach } from "vitest";
import { getSession, setSession, hasSession, clearSessions, sessions } from "./state.js";
import type { AuditSession } from "./types.js";

describe("State Management", () => {
  beforeEach(() => {
    clearSessions();
  });

  it("should initially have no sessions", () => {
    expect(sessions.size).toBe(0);
  });

  it("should return undefined for a non-existent session", () => {
    expect(getSession("invalid_id")).toBeUndefined();
    expect(hasSession("invalid_id")).toBe(false);
  });

  it("should set and get a session correctly", () => {
    const mockSession: AuditSession = {
      id: "session_123",
      framework: "owasp",
      results: [],
      startedAt: new Date().toISOString(),
    };

    setSession("session_123", mockSession);

    expect(hasSession("session_123")).toBe(true);
    expect(getSession("session_123")).toEqual(mockSession);
    expect(sessions.size).toBe(1);
  });

  it("should clear all sessions", () => {
    const mockSession: AuditSession = {
      id: "session_123",
      framework: "owasp",
      results: [],
      startedAt: new Date().toISOString(),
    };

    setSession("session_123", mockSession);
    expect(sessions.size).toBe(1);

    clearSessions();
    expect(sessions.size).toBe(0);
    expect(hasSession("session_123")).toBe(false);
  });
});
