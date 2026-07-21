import { describe, it, expect } from "vitest";
import { server } from "./index.js";

describe("server initialization", () => {
  it("should have instantiated an McpServer and exposed tools", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });
});
