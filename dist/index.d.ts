#!/usr/bin/env node
/**
 * security-audit-mcp
 * MCP server for AI-powered security audits
 * Frameworks: OWASP Top 10, NIST SP 800-53, ISO 27001
 * Author: Nasima Shaoz
 * License: MIT
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { AuditSession } from "./types.js";
export declare const server: McpServer;
export declare const sessions: Map<string, AuditSession>;
//# sourceMappingURL=index.d.ts.map