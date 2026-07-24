import { describe, it, expect, vi } from "vitest";
import { server, main } from "./index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        start: vi.fn(),
        close: vi.fn()
      };
    })
  };
});

describe("Server Integration", () => {
  it("should initialize the MCP server instance", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });

  it("should connect via StdioServerTransport in main()", async () => {
    const connectSpy = vi.spyOn(server, 'connect').mockResolvedValue(undefined as never);
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await main();

    expect(StdioServerTransport).toHaveBeenCalled();
    expect(connectSpy).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("running on stdio"));

    connectSpy.mockRestore();
    consoleSpy.mockRestore();
  });
});
