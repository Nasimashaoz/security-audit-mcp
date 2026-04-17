import { describe, it, expect, vi } from 'vitest';

// We just test if index.ts compiles and executes without crashing when imported
describe('Server Initialization', () => {
  it('should initialize without throwing errors', async () => {
    // Mock the SDK's StdioServerTransport and McpServer
    const originalConsoleError = console.error;
    console.error = vi.fn(); // Suppress expected console.error from index.ts main()

    let serverInitialized = false;

    try {
      // Import runs the index.js side effects (like creating McpServer and calling main)
      await import('./index.js');
      serverInitialized = true;
    } catch (e) {
      serverInitialized = false;
    }

    expect(serverInitialized).toBe(true);

    // Restore original console.error
    console.error = originalConsoleError;
  });
});
