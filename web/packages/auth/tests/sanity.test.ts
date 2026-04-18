import { describe, it, expect } from 'vitest';
import { VERSION } from '../src';

describe('@triton/auth', () => {
  it('exports a version constant', () => {
    expect(VERSION).toBe('0.0.0');
  });
});
