import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { useToast, __resetToastsForTest } from '../src/composables/useToast';
import TToastHost from '../src/composite/TToastHost.vue';

describe('useToast', () => {
  beforeEach(() => __resetToastsForTest());

  it('success adds a toast to the host', async () => {
    const w = mount(TToastHost, { attachTo: document.body });
    const toast = useToast();
    toast.success({ title: 'Saved' });
    await w.vm.$nextTick();
    expect(w.text()).toContain('Saved');
    w.unmount();
  });

  it.each(['success', 'warn', 'error', 'info'] as const)(
    'toast.%s produces correct variant class',
    async (kind) => {
      const w = mount(TToastHost, { attachTo: document.body });
      const toast = useToast();
      toast[kind]({ title: `t-${kind}` });
      await w.vm.$nextTick();
      expect(w.find(`.t-toast--${kind}`).exists()).toBe(true);
      w.unmount();
    }
  );

  it('dismiss removes the toast', async () => {
    const w = mount(TToastHost, { attachTo: document.body });
    const toast = useToast();
    const id = toast.info({ title: 'hi' });
    await w.vm.$nextTick();
    toast.dismiss(id);
    await w.vm.$nextTick();
    expect(w.findAll('.t-toast')).toHaveLength(0);
    w.unmount();
  });
});
