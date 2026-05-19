import { describe, it, expect } from "vitest";
import { FRAMEWORKS } from "./frameworks.js";

describe("Frameworks", () => {
  it("should contain all required frameworks", () => {
    const requiredFrameworks = ["owasp", "nist", "iso27001", "pcidss", "soc2", "hipaa", "cisv8"];
    requiredFrameworks.forEach((fwKey) => {
      expect(FRAMEWORKS).toHaveProperty(fwKey);
    });
  });

  it("each framework should have required properties", () => {
    Object.values(FRAMEWORKS).forEach((fw) => {
      expect(fw).toHaveProperty("name");
      expect(typeof fw.name).toBe("string");

      expect(fw).toHaveProperty("version");
      expect(typeof fw.version).toBe("string");

      expect(fw).toHaveProperty("description");
      expect(typeof fw.description).toBe("string");

      expect(fw).toHaveProperty("items");
      expect(Array.isArray(fw.items)).toBe(true);
      expect(fw.items.length).toBeGreaterThan(0);
    });
  });

  it("each framework item should have valid properties and risk levels", () => {
    const validRisks = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
    Object.values(FRAMEWORKS).forEach((fw) => {
      fw.items.forEach((item) => {
        expect(item).toHaveProperty("id");
        expect(typeof item.id).toBe("string");

        expect(item).toHaveProperty("title");
        expect(typeof item.title).toBe("string");

        expect(item).toHaveProperty("description");
        expect(typeof item.description).toBe("string");

        expect(item).toHaveProperty("risk");
        expect(validRisks).toContain(item.risk);
      });
    });
  });
});
