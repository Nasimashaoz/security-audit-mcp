import { describe, it, expect, vi } from 'vitest';
import { server, main } from './index.js';
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

describe('Index / MCP Server', () => {
  it('server instance should be defined', () => {
    expect(server).toBeDefined();
  });

  it('main function should initialize server transport', async () => {
    const connectSpy = vi.spyOn(server, 'connect').mockResolvedValue(undefined);

    await main();

    expect(StdioServerTransport).toHaveBeenCalled();
    expect(connectSpy).toHaveBeenCalled();
    connectSpy.mockRestore();
  });
});
