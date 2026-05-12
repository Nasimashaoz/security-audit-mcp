import { describe, it, expect } from 'vitest';
import { FRAMEWORKS } from '../frameworks.js';

describe('FRAMEWORKS', () => {
  it('should have owasp framework', () => {
    expect(FRAMEWORKS.owasp).toBeDefined();
    expect(FRAMEWORKS.owasp.name).toBe('OWASP Top 10');
    expect(FRAMEWORKS.owasp.items.length).toBeGreaterThan(0);
  });

  it('should have nist framework', () => {
    expect(FRAMEWORKS.nist).toBeDefined();
    expect(FRAMEWORKS.nist.name).toBe('NIST SP 800-53');
    expect(FRAMEWORKS.nist.items.length).toBeGreaterThan(0);
  });

  it('should have iso27001 framework', () => {
    expect(FRAMEWORKS.iso27001).toBeDefined();
    expect(FRAMEWORKS.iso27001.name).toBe('ISO 27001');
    expect(FRAMEWORKS.iso27001.items.length).toBeGreaterThan(0);
  });
});
