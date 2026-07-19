import { describe, it, expect, vi } from "vitest";
import { server } from "./index.js";

// Mock StdioServerTransport
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    },
  };
});

describe("Server", () => {
  it("should initialize server with tools", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });
});
