import { describe, it, expect } from 'vitest';
import { VERSION } from '../src';

describe('@triton/ui', () => {
  it('exports a version constant', () => {
    expect(VERSION).toBe('0.0.0');
  });
});
