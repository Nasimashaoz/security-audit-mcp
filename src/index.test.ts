import { describe, it, expect, vi } from "vitest";
import { server, main } from "./index.js";

// Mock the StdioServerTransport to test main()
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: class {
      constructor() {}
      start() {}
      close() {}
    }
  };
});

describe("Server Index", () => {
  it("should define the server instance", () => {
    expect(server).toBeDefined();
  });

  it("should execute main without error", async () => {
    const connectSpy = vi.spyOn(server, "connect").mockResolvedValue(undefined);
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await main();

    expect(connectSpy).toHaveBeenCalled();
    expect(consoleSpy).toHaveBeenCalledWith("🔐 security-audit-mcp server running on stdio");

    connectSpy.mockRestore();
    consoleSpy.mockRestore();
  });
});
