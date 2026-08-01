import { describe, it, expect } from "vitest";
import { server } from "../index.js";

describe("MCP Server", () => {
  it("should be defined and expose a tool registration method", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });
});
