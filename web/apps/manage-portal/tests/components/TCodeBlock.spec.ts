import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import TCodeBlock from '../../src/components/TCodeBlock.vue';

describe('TCodeBlock', () => {
  it('renders the code', () => {
    const w = mount(TCodeBlock, { props: { code: 'secret-pw-123' } });
    expect(w.text()).toContain('secret-pw-123');
  });

  it('copies to clipboard on button click', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const w = mount(TCodeBlock, { props: { code: 'abc' } });
    await w.find('button').trigger('click');
    expect(writeText).toHaveBeenCalledWith('abc');
  });
});
