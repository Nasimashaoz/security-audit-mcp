import { describe, it, expect } from "vitest";
import { server } from "./index.js";

describe("MCP Server", () => {
  it("instantiates the server successfully", () => {
    expect(server).toBeDefined();
    expect(server).toHaveProperty("tool");
    expect(typeof server.tool).toBe("function");
  });
});
