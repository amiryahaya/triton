import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { useToast, __resetToastsForTest } from '../src/composables/useToast';
import TToastHost from '../src/composite/TToastHost.vue';

// TToastHost uses <Teleport to="body">, so the DOM lands on document.body
// rather than inside the Vue Test Utils wrapper. Query the real DOM.

describe('useToast', () => {
  beforeEach(() => __resetToastsForTest());
  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('success adds a toast to the host', async () => {
    const w = mount(TToastHost, { attachTo: document.body });
    const toast = useToast();
    toast.success({ title: 'Saved' });
    await w.vm.$nextTick();
    expect(document.body.textContent).toContain('Saved');
    w.unmount();
  });

  it.each(['success', 'warn', 'error', 'info'] as const)(
    'toast.%s produces correct variant class',
    async (kind) => {
      const w = mount(TToastHost, { attachTo: document.body });
      const toast = useToast();
      toast[kind]({ title: `t-${kind}` });
      await w.vm.$nextTick();
      expect(document.querySelector(`.t-toast--${kind}`)).not.toBeNull();
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
    expect(document.querySelectorAll('.t-toast')).toHaveLength(0);
    w.unmount();
  });
});
