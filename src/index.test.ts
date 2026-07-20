import { describe, it, expect, vi } from 'vitest';
import { server } from './index.js';

vi.mock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
  StdioServerTransport: class {
    async start() {}
    async close() {}
  }
}));

describe('Server initialization', () => {
  it('should initialize the server correctly', () => {
    expect(server).toBeDefined();

    // Assert standard interface methods exist
    expect(typeof server.tool).toBe('function');
  });
});
