import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TInput from '../src/atoms/TInput.vue';
import TSelect from '../src/atoms/TSelect.vue';
import TFormField from '../src/atoms/TFormField.vue';

describe('TInput', () => {
  it('renders value via v-model', () => {
    const w = mount(TInput, { props: { modelValue: 'hello' } });
    expect((w.element as HTMLInputElement).value).toBe('hello');
  });

  it('emits update:modelValue on input', async () => {
    const w = mount(TInput, { props: { modelValue: '' } });
    await w.setValue('abc');
    const evs = w.emitted('update:modelValue');
    expect(evs?.[0]?.[0]).toBe('abc');
  });

  it('applies error class when error prop truthy', () => {
    const w = mount(TInput, { props: { modelValue: 'x', error: true } });
    expect(w.classes()).toContain('is-error');
  });
});

describe('TSelect', () => {
  it('renders option slot', () => {
    const w = mount(TSelect, {
      props: { modelValue: 'a' },
      slots: { default: '<option value="a">A</option><option value="b">B</option>' }
    });
    expect(w.findAll('option')).toHaveLength(2);
  });
});

describe('TFormField', () => {
  it('renders label and required marker', () => {
    const w = mount(TFormField, {
      props: { label: 'Name', required: true },
      slots: { default: '<input />' }
    });
    expect(w.text()).toContain('Name');
    expect(w.find('.t-req').exists()).toBe(true);
  });

  it('shows error text when error prop set', () => {
    const w = mount(TFormField, {
      props: { label: 'Email', error: 'Invalid address' },
      slots: { default: '<input />' }
    });
    expect(w.find('.t-field-error').text()).toBe('Invalid address');
  });

  it('shows hint text when hint prop set and no error', () => {
    const w = mount(TFormField, {
      props: { label: 'Email', hint: 'We never share this.' },
      slots: { default: '<input />' }
    });
    expect(w.find('.t-field-hint').text()).toBe('We never share this.');
    expect(w.find('.t-field-error').exists()).toBe(false);
  });
});
