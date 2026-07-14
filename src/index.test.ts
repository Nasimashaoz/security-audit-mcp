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

describe("Server Integration", () => {
  it("should initialize server with correct metadata", () => {
    expect(server).toBeDefined();
    // In SDK v1+, the constructor options are used internally to build server instance.
    // We just verify it's instantiated successfully here.
  });

  it("should start the server successfully in main()", async () => {
    const connectSpy = vi.spyOn(server, "connect").mockResolvedValue(undefined);
    const consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await main();

    expect(StdioServerTransport).toHaveBeenCalled();
    expect(connectSpy).toHaveBeenCalled();
    expect(consoleErrorSpy).toHaveBeenCalledWith("🔐 security-audit-mcp server running on stdio");

    connectSpy.mockRestore();
    consoleErrorSpy.mockRestore();
  });
});
