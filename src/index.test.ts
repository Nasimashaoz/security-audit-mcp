import { describe, it, expect, vi } from "vitest";
import { server } from "./index.js";

// Mock the StdioServerTransport to prevent real stdio connection in tests
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    },
  };
});

describe("Server Initialization", () => {
  it("should initialize the server instance", () => {
    expect(server).toBeDefined();
    // Verify that the server has the expected structure and tool function
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });
});
