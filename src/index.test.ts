import { describe, it, expect, vi } from "vitest";
import { server, main } from "./index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => {
  return {
    StdioServerTransport: vi.fn().mockImplementation(() => ({
      start: vi.fn(),
      close: vi.fn(),
    })),
  };
});

describe("Server Integration", () => {
  it("server instance is defined and exposes tool registration", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });

  it("main function connects transport", async () => {
    const connectSpy = vi.spyOn(server, "connect").mockResolvedValue(undefined);
    await main();
    expect(StdioServerTransport).toHaveBeenCalled();
    expect(connectSpy).toHaveBeenCalled();
    connectSpy.mockRestore();
  });
});
