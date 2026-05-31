import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        'vitest.config.ts',
        '**/*.test.ts',
        '**/*.spec.ts'
      ]
    }
  }
})
