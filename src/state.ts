import type { AuditSession } from "./types.js";

// In-memory session storage
export const sessions = new Map<string, AuditSession>();

export function getSession(id: string): AuditSession | undefined {
  return sessions.get(id);
}

export function setSession(id: string, session: AuditSession): void {
  sessions.set(id, session);
}

export function hasSession(id: string): boolean {
  return sessions.has(id);
}

export function clearSessions(): void {
  sessions.clear();
}
