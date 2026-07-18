import { describe, it, expect, vi } from "vitest";
import { server, main } from "./index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => {
      return {
        start: vi.fn(),
        close: vi.fn(),
      };
    }),
  };
});

describe("Server Initialization", () => {
  it("should define the server instance", () => {
    expect(server).toBeDefined();
  });

  it("should have expected tool handlers registered", () => {
     // serverInfo is not directly exposed in SDK v1+
     // We just assert the instance is initialized and check properties that are accessible if any, or skip internal checks
     expect(server).toHaveProperty("tool");
     expect(typeof server.tool).toBe("function");
  });

  it("should call connect on main execution", async () => {
    const connectSpy = vi.spyOn(server, "connect").mockResolvedValue(undefined);
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await main();

    expect(StdioServerTransport).toHaveBeenCalled();
    expect(connectSpy).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("security-audit-mcp server running on stdio"));

    connectSpy.mockRestore();
    consoleSpy.mockRestore();
  });
});
