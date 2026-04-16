import { describe, it, expect } from 'vitest';
import { FRAMEWORKS } from '../src/frameworks.js';
import type { Framework } from '../src/types.js';

describe('FRAMEWORKS', () => {
  it('should contain all required frameworks', () => {
    const requiredFrameworks = ['owasp', 'nist', 'iso27001', 'pcidss', 'soc2', 'hipaa', 'cisv8'];
    const keys = Object.keys(FRAMEWORKS);

    for (const fw of requiredFrameworks) {
      expect(keys).toContain(fw);
    }
  });

  it('each framework should conform to the Framework schema', () => {
    for (const [key, fw] of Object.entries(FRAMEWORKS)) {
      expect(fw).toHaveProperty('name');
      expect(fw).toHaveProperty('version');
      expect(fw).toHaveProperty('description');
      expect(fw).toHaveProperty('items');
      expect(Array.isArray(fw.items)).toBe(true);
      expect(fw.items.length).toBeGreaterThan(0);

      for (const item of fw.items) {
        expect(item).toHaveProperty('id');
        expect(item).toHaveProperty('title');
        expect(item).toHaveProperty('description');
        expect(item).toHaveProperty('risk');
        expect(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).toContain(item.risk);
      }
    }
  });
});
