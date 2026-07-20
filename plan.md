1. Refactor `src/index.ts` to extract tool handler logic into a new `src/handlers.ts` file, ensuring separation of concerns and enabling testability independent of SDK state.
2. Implement the missing `cve_lookup` tool, which queries the MITRE API with sanitized inputs using `encodeURIComponent()` to avoid injection.
3. Refactor `src/index.ts` to eliminate hardcoded framework arrays (like `["owasp", "nist", "iso27001"]`) in Zod schemas. Instead, generate enums dynamically using `Object.keys(FRAMEWORKS) as [string, ...string[]]`.
4. Ensure the returned objects from tool handlers cast their type to `as const` (e.g., `type: "text" as const`) to satisfy `@modelcontextprotocol/sdk` schemas.
5. In `src/index.ts`, export the server instance and only execute `main()` if the environment is not a test environment (`process.env.NODE_ENV !== 'test'`).
6. Update `tsconfig.json` to explicitly exclude test files (e.g., `src/**/*.test.ts`) from compilation.
7. Create test scripts in `src/handlers.test.ts` and `src/index.test.ts` to cover all tool functionality. Mock the `fetch` function for `cve_lookup`, use `vi.useFakeTimers()` for audit timing, and assert the server instantiation using standard methods without accessing internal SDK state.
8. Complete pre-commit steps to ensure proper testing, verification, review, and reflection are done.
