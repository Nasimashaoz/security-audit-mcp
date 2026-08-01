import { describe, it, expect, beforeEach } from "vitest";
import { getSession, setSession, hasSession, clearSessions } from "../state.js";

describe("State Management", () => {
  beforeEach(() => {
    clearSessions();
  });

  it("should return false for non-existent session", () => {
    expect(hasSession("unknown")).toBe(false);
    expect(getSession("unknown")).toBeUndefined();
  });

  it("should set and retrieve a session", () => {
    const session = {
      id: "test1",
      framework: "owasp",
      results: [],
      startedAt: "2023-01-01T00:00:00.000Z",
    };

    setSession("test1", session);
    expect(hasSession("test1")).toBe(true);
    expect(getSession("test1")).toEqual(session);
  });

  it("should clear all sessions", () => {
    setSession("test2", { id: "test2", framework: "nist", results: [], startedAt: "" });
    expect(hasSession("test2")).toBe(true);

    clearSessions();
    expect(hasSession("test2")).toBe(false);
  });
});
