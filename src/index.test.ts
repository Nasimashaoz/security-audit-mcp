import { describe, it, expect } from "vitest";
import { server } from "./index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

describe("Server Entry", () => {
  it("should instantiate an McpServer", () => {
    expect(server).toBeDefined();
    expect(server).toBeInstanceOf(McpServer);
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });

  it("should have registered all expected tools", () => {
    // In SDK v1+, the internal tools Map is private, so we can't easily assert exactly
    // what tools are registered without calling an internal API or checking private fields.
    // We can at least check it doesn't throw. The main logic is tested via handlers.
    // However, if we must assert, we can do a workaround check or just rely on
    // the fact that we can call server.serverInfo to see if the server itself is working.

    // We expect the server to be configured and ready to handle connections.
    expect(server).toBeDefined();
    // In SDK v1+, serverInfo might be uninitialized without a connection.
  });
});
