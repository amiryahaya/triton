import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { useAdminKey } from '../src/adminKey';

describe('useAdminKey', () => {
  beforeEach(() => {
    // Tear down any prior singleton state so each spec re-initialises
    // from a clean sessionStorage.
    useAdminKey().stop();
    sessionStorage.clear();
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('loads stored key on init', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const a = useAdminKey();
    expect(a.key.value).toBe('abc');
    a.stop();
  });

  it('setKey stores in sessionStorage and sets key.value', () => {
    const a = useAdminKey();
    a.setKey('xyz');
    expect(sessionStorage.getItem('triton_admin_key')).toBe('xyz');
    expect(a.key.value).toBe('xyz');
    a.stop();
  });

  it('clear removes key', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const a = useAdminKey();
    a.clear();
    expect(sessionStorage.getItem('triton_admin_key')).toBeNull();
    expect(a.key.value).toBe('');
    a.stop();
  });

  it('clears after 30m of no activity', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const a = useAdminKey();
    vi.advanceTimersByTime(30 * 60 * 1000 + 1_000);
    expect(a.key.value).toBe('');
    a.stop();
  });

  it('activity resets the idle clock', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const a = useAdminKey();
    vi.advanceTimersByTime(10 * 60 * 1000);
    a.touch();
    vi.advanceTimersByTime(25 * 60 * 1000);
    expect(a.key.value).toBe('abc');
    a.stop();
  });
});
