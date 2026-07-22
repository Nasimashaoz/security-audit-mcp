import { describe, it, expect, vi } from "vitest";
import { server } from "./index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => ({
      start: vi.fn(),
      close: vi.fn(),
    })),
  };
});

describe("Index / Server Initialization", () => {
  it("should instantiate the server successfully", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });
});
