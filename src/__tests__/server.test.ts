import { describe, it, expect } from 'vitest';
import { server } from '../index.js';

describe('Server', () => {
  it('should initialize and register tools correctly', () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty('tool');
    expect(typeof server.tool).toBe('function');
  });
});
