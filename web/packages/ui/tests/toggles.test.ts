import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TToggle from '../src/atoms/TToggle.vue';
import TCheckbox from '../src/atoms/TCheckbox.vue';

describe('TToggle', () => {
  it('shows on-state visually when modelValue=true', () => {
    const w = mount(TToggle, { props: { modelValue: true } });
    expect(w.classes()).toContain('is-on');
  });

  it('emits update on click', async () => {
    const w = mount(TToggle, { props: { modelValue: false } });
    await w.trigger('click');
    const evs = w.emitted('update:modelValue');
    expect(evs?.[0]?.[0]).toBe(true);
  });

  it('does not emit when disabled', async () => {
    const w = mount(TToggle, { props: { modelValue: false, disabled: true } });
    await w.trigger('click');
    expect(w.emitted('update:modelValue')).toBeUndefined();
  });
});

describe('TCheckbox', () => {
  it('emits update on click', async () => {
    const w = mount(TCheckbox, { props: { modelValue: false } });
    await w.trigger('click');
    expect(w.emitted('update:modelValue')?.[0]?.[0]).toBe(true);
  });
});
