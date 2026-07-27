import type { AuditSession } from "./types.js";

const sessions = new Map<string, AuditSession>();

export function getSession(sessionId: string): AuditSession | undefined {
  return sessions.get(sessionId);
}

export function setSession(sessionId: string, session: AuditSession): void {
  sessions.set(sessionId, session);
}

export function hasSession(sessionId: string): boolean {
  return sessions.has(sessionId);
}

export function clearSessions(): void {
  sessions.clear();
}
