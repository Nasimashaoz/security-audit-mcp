import { describe, it, expect } from 'vitest';
import { server } from '../index.js';

describe('MCP Server Integration', () => {
  it('instantiates and exports the server correctly', () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty('tool');
    expect(typeof server.tool).toBe('function');
  });

});
