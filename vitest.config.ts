import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: ['**/node_modules/**', '**/dist/**', '**/tests/**', '**/*.test.ts'],
      thresholds: {
        lines: 98,
        statements: 98,
        functions: 100,
        branches: 82,
      }
    },
  },
});
