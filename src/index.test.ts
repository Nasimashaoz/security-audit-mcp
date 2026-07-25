import { describe, it, expect, vi } from 'vitest';
import { server, main } from './index.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => {
  return {
    StdioServerTransport: class {
      start() {}
      close() {}
    }
  };
});

describe('MCP Server', () => {
  it('instantiates the server', () => {
    expect(server).toBeDefined();
  });

  it('exposes the tool registration function', () => {
    expect(server).toHaveProperty('tool');
    expect(typeof server.tool).toBe('function');
  });

  it('starts the server on main()', async () => {
      const connectSpy = vi.spyOn(server, 'connect').mockResolvedValue(undefined as any);
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      await main();

      expect(connectSpy).toHaveBeenCalled();
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("security-audit-mcp server running on stdio"));
  })
});
