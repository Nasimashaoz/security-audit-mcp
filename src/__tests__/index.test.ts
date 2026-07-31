import { describe, it, expect } from "vitest";
import { server } from "../index.js";

describe("MCP Server", () => {
  it("should be instantiated", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });
});
