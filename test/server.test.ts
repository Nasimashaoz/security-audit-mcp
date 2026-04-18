import { describe, it, expect, beforeEach } from "vitest";
import { FRAMEWORKS } from "../src/frameworks.js";
import { sessions } from "../src/index.js";
import { server } from "../src/index.js";

describe("Security Audit MCP Server Tools", () => {
  beforeEach(() => {
    sessions.clear();
  });

  it("should have all expected frameworks in FRAMEWORKS", () => {
    const expectedKeys = ["owasp", "nist", "iso27001", "pcidss", "soc2", "hipaa", "cisv8"];
    expectedKeys.forEach((key) => {
      expect(FRAMEWORKS).toHaveProperty(key);
      expect(FRAMEWORKS[key]).toHaveProperty("name");
      expect(FRAMEWORKS[key].items.length).toBeGreaterThan(0);
    });
  });

  it("should have correctly populated framework items with valid risk levels", () => {
    const validRisks = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    Object.values(FRAMEWORKS).forEach((fw) => {
      fw.items.forEach((item) => {
        expect(validRisks).toContain(item.risk);
        expect(item).toHaveProperty("id");
        expect(item).toHaveProperty("title");
        expect(item).toHaveProperty("description");
      });
    });
  });

  it("should initialize with an empty sessions map", () => {
    expect(sessions.size).toBe(0);
  });

  it("should expose McpServer instance", () => {
    expect(server).toBeDefined();
    expect(server.server).toBeDefined();
  });
});
