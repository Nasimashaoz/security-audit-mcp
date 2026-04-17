import { describe, it, expect } from 'vitest';
import { FRAMEWORKS } from './frameworks.js';
import type { Framework, FrameworkItem } from './types.js';

describe('Frameworks Definition', () => {
  it('should contain all required framework keys', () => {
    const expectedKeys = ['owasp', 'nist', 'iso27001', 'pci-dss', 'soc2', 'hipaa', 'cis-v8'];
    const actualKeys = Object.keys(FRAMEWORKS);

    expectedKeys.forEach(key => {
      expect(actualKeys).toContain(key);
    });
  });

  it('should have valid properties for each framework', () => {
    for (const [key, _framework] of Object.entries(FRAMEWORKS)) {
      const framework = _framework as Framework;
      expect(framework).toHaveProperty('name');
      expect(typeof framework.name).toBe('string');

      expect(framework).toHaveProperty('version');
      expect(typeof framework.version).toBe('string');

      expect(framework).toHaveProperty('description');
      expect(typeof framework.description).toBe('string');

      expect(framework).toHaveProperty('items');
      expect(Array.isArray(framework.items)).toBe(true);
      expect(framework.items.length).toBeGreaterThan(0);
    }
  });

  it('should have valid items within each framework', () => {
    const validRisks = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

    for (const [key, _framework] of Object.entries(FRAMEWORKS)) {
      const framework = _framework as Framework;
      framework.items.forEach((item: FrameworkItem, index: number) => {
        expect(item, `Item at index ${index} in framework ${key} is invalid`).toBeDefined();

        expect(typeof item.id, `Invalid id in item at index ${index} in framework ${key}`).toBe('string');
        expect(item.id.length).toBeGreaterThan(0);

        expect(typeof item.title, `Invalid title in item at index ${index} in framework ${key}`).toBe('string');
        expect(item.title.length).toBeGreaterThan(0);

        expect(typeof item.description, `Invalid description in item at index ${index} in framework ${key}`).toBe('string');
        expect(item.description.length).toBeGreaterThan(0);

        expect(validRisks, `Invalid risk in item at index ${index} in framework ${key}`).toContain(item.risk);
      });
    }
  });
});
