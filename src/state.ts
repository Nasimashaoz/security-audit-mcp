import type { AuditSession } from "./types.js";

// In-memory session storage
export const sessions = new Map<string, AuditSession>();
