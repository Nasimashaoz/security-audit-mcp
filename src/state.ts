import type { AuditSession } from "./types.js";

export const sessions = new Map<string, AuditSession>();

export function clearSessions() {
  sessions.clear();
}
