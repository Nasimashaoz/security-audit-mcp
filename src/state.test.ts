import { describe, it, expect, beforeEach } from "vitest";
import { getSession, setSession, clearSessions } from "./state.js";
import type { AuditSession } from "./types.js";

describe("State Management", () => {
  beforeEach(() => {
    clearSessions();
  });

  it("should return undefined for a non-existent session", () => {
    expect(getSession("unknown-id")).toBeUndefined();
  });

  it("should set and retrieve a session", () => {
    const session: AuditSession = {
      id: "test-session",
      framework: "owasp",
      results: [],
      startedAt: new Date().toISOString(),
    };
    setSession("test-session", session);

    const retrieved = getSession("test-session");
    expect(retrieved).toBeDefined();
    expect(retrieved?.id).toBe("test-session");
    expect(retrieved?.framework).toBe("owasp");
  });

  it("should clear all sessions", () => {
    const session: AuditSession = {
      id: "test-session-2",
      framework: "nist",
      results: [],
      startedAt: new Date().toISOString(),
    };
    setSession("test-session-2", session);

    expect(getSession("test-session-2")).toBeDefined();
    clearSessions();
    expect(getSession("test-session-2")).toBeUndefined();
  });
});
