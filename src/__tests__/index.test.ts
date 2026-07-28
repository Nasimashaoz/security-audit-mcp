import { describe, it, expect, vi } from "vitest";
import { server } from "../index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    },
  };
});

describe("Server Registration", () => {
  it("server instance is created and exposes tools", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });
});
