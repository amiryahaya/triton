import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TButton from '../src/atoms/TButton.vue';

describe('TButton', () => {
  it('renders slot content', () => {
    const w = mount(TButton, { slots: { default: 'Save' } });
    expect(w.text()).toBe('Save');
  });

  it('applies variant class (default primary)', () => {
    const w = mount(TButton);
    expect(w.classes()).toContain('t-btn--primary');
  });

  it.each(['primary', 'secondary', 'ghost', 'danger'] as const)(
    'applies variant=%s class',
    (variant) => {
      const w = mount(TButton, { props: { variant } });
      expect(w.classes()).toContain(`t-btn--${variant}`);
    }
  );

  it.each(['sm', 'md', 'lg'] as const)('applies size=%s class', (size) => {
    const w = mount(TButton, { props: { size } });
    expect(w.classes()).toContain(`t-btn--${size}`);
  });

  it('propagates disabled attribute', () => {
    const w = mount(TButton, { props: { disabled: true } });
    expect(w.attributes('disabled')).toBeDefined();
    expect(w.classes()).toContain('is-disabled');
  });

  it('emits click', async () => {
    const w = mount(TButton);
    await w.trigger('click');
    expect(w.emitted('click')).toHaveLength(1);
  });

  it('does not emit click when disabled', async () => {
    const w = mount(TButton, { props: { disabled: true } });
    await w.trigger('click');
    expect(w.emitted('click')).toBeUndefined();
  });
});
