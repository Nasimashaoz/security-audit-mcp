import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: [
        "node_modules/",
        "dist/",
        "src/tests/**/*.ts",
        "**/*.test.ts",
        "**/*.spec.ts",
        "vitest.config.ts"
      ],
    },
  },
});
