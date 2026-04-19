import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TLoginPrompt from '../src/TLoginPrompt.vue';

describe('TLoginPrompt', () => {
  it('renders email and password inputs', () => {
    const w = mount(TLoginPrompt);
    expect(w.find('input[type="email"]').exists()).toBe(true);
    expect(w.find('input[type="password"]').exists()).toBe(true);
  });

  it('emits submit with trimmed credentials on form submit', async () => {
    const w = mount(TLoginPrompt);
    await w.find('input[type="email"]').setValue('  alice@acme.test  ');
    await w.find('input[type="password"]').setValue('hunter2');
    await w.find('form').trigger('submit');
    const emitted = w.emitted('submit');
    expect(emitted).toHaveLength(1);
    expect(emitted?.[0]?.[0]).toEqual({ email: 'alice@acme.test', password: 'hunter2' });
  });

  it('does not emit when email is blank', async () => {
    const w = mount(TLoginPrompt);
    await w.find('input[type="password"]').setValue('hunter2');
    await w.find('form').trigger('submit');
    expect(w.emitted('submit')).toBeUndefined();
  });

  it('shows error message from prop', () => {
    const w = mount(TLoginPrompt, { props: { error: 'Invalid credentials' } });
    expect(w.text()).toContain('Invalid credentials');
  });

  it('disables submit when busy', () => {
    const w = mount(TLoginPrompt, { props: { busy: true } });
    expect((w.find('button[type="submit"]').element as HTMLButtonElement).disabled).toBe(true);
  });
});
