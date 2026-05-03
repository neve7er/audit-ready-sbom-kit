import { describe, it, expect } from 'vitest';
import { buildPurl } from '../../src/core/utils/purl';

describe('buildPurl', () => {
  it('should handle unscoped package', () => {
    expect(buildPurl('lodash', '4.17.21')).toBe('pkg:npm/lodash@4.17.21');
  });

  it('should handle scoped package', () => {
    expect(buildPurl('@scope/name', '1.0.0')).toBe('pkg:npm/%40scope%2Fname@1.0.0');
  });

  it('should handle pre-release version', () => {
    expect(buildPurl('react', '18.0.0-beta.1')).toBe('pkg:npm/react@18.0.0-beta.1');
  });

  it('should handle build metadata', () => {
    expect(buildPurl('react', '1.0.0+sha.123')).toBe('pkg:npm/react@1.0.0+sha.123');
  });

  it('should handle hyphenated name', () => {
    expect(buildPurl('my-package', '2.0.0')).toBe('pkg:npm/my-package@2.0.0');
  });

  it('should handle dot in name', () => {
    expect(buildPurl('my-package.js', '1.0.0')).toBe('pkg:npm/my-package.js@1.0.0');
  });

  it('should handle deep path name', () => {
    expect(buildPurl('deep/nested/path', '1.0.0')).toBe('pkg:npm/deep%2Fnested%2Fpath@1.0.0');
  });

  it('should handle scoped package with pre-release', () => {
    expect(buildPurl('@org/lib', '2.0.0-alpha.1')).toBe('pkg:npm/%40org%2Flib@2.0.0-alpha.1');
  });
});