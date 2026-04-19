import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import TAuthGate from '../src/TAuthGate.vue';
import { useJwt } from '../src/jwt';

function makeToken(claims: Record<string, unknown>): string {
  const h = btoa(JSON.stringify({ alg: 'HS256' }));
  const p = btoa(JSON.stringify(claims));
  return `${h}.${p}.sig`;
}

describe('TAuthGate (adminKey)', () => {
  beforeEach(() => sessionStorage.clear());

  it('shows prompt when no key stored', () => {
    const w = mount(TAuthGate, {
      props: { type: 'adminKey' },
      slots: { default: '<div class="inner">app</div>' },
    });
    expect(w.find('.t-admin-prompt').exists()).toBe(true);
    expect(w.find('.inner').exists()).toBe(false);
  });

  it('renders default slot when key stored', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const w = mount(TAuthGate, {
      props: { type: 'adminKey' },
      slots: { default: '<div class="inner">app</div>' },
    });
    expect(w.find('.inner').exists()).toBe(true);
  });
});

describe('TAuthGate (jwt)', () => {
  beforeEach(() => {
    localStorage.clear();
    useJwt().clear();
  });

  it('shows login prompt when no token', () => {
    const w = mount(TAuthGate, {
      props: { type: 'jwt' },
      slots: { default: '<div class="inner">app</div>' },
    });
    expect(w.find('.t-login-prompt').exists()).toBe(true);
    expect(w.find('.inner').exists()).toBe(false);
  });

  it('renders default slot when valid token present', () => {
    useJwt().setToken(makeToken({ sub: 'u', exp: 9_999_999_999 }));
    const w = mount(TAuthGate, {
      props: { type: 'jwt' },
      slots: { default: '<div class="inner">app</div>' },
    });
    expect(w.find('.inner').exists()).toBe(true);
  });

  it('shows login prompt when token is expired', () => {
    useJwt().setToken(makeToken({ sub: 'u', exp: 1 }));
    const w = mount(TAuthGate, {
      props: { type: 'jwt' },
      slots: { default: '<div class="inner">app</div>' },
    });
    expect(w.find('.t-login-prompt').exists()).toBe(true);
    expect(w.find('.inner').exists()).toBe(false);
  });

  it('forwards prompt submit as login event', async () => {
    const w = mount(TAuthGate, {
      props: { type: 'jwt' },
      slots: { default: '<div class="inner">app</div>' },
    });
    await w.find('input[type="email"]').setValue('a@b.com');
    await w.find('input[type="password"]').setValue('pw');
    await w.find('form').trigger('submit');
    const emitted = w.emitted('login');
    expect(emitted).toHaveLength(1);
    expect(emitted?.[0]?.[0]).toEqual({ email: 'a@b.com', password: 'pw' });
  });

  it('forwards error prop to login prompt', () => {
    const w = mount(TAuthGate, {
      props: { type: 'jwt', error: 'Invalid credentials' },
      slots: { default: '<div class="inner">app</div>' },
    });
    expect(w.text()).toContain('Invalid credentials');
  });
});
