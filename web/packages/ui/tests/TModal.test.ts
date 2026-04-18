import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TModal from '../src/composite/TModal.vue';
import TConfirmDialog from '../src/composite/TConfirmDialog.vue';

describe('TModal', () => {
  it('renders when open=true', () => {
    const w = mount(TModal, {
      props: { open: true, title: 'Test' },
      slots: { default: '<p>body</p>' },
      attachTo: document.body,
    });
    expect(document.querySelector('.t-modal')).not.toBeNull();
    w.unmount();
  });

  it('does not render when open=false', () => {
    const w = mount(TModal, {
      props: { open: false, title: 'Test' },
      attachTo: document.body,
    });
    expect(document.querySelector('.t-modal')).toBeNull();
    w.unmount(); // unmount so ESC listener doesn't leak into later tests
  });

  it('emits close on backdrop click', async () => {
    const w = mount(TModal, {
      props: { open: true, title: 'Test' },
      slots: { default: 'body' },
      attachTo: document.body,
    });
    const backdrop = document.querySelector('.t-modal-backdrop') as HTMLElement;
    backdrop.click();
    await w.vm.$nextTick();
    expect(w.emitted('close')).toHaveLength(1);
    w.unmount();
  });

  it('emits close on ESC', async () => {
    const w = mount(TModal, {
      props: { open: true, title: 'Test' },
      slots: { default: 'body' },
      attachTo: document.body,
    });
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await w.vm.$nextTick();
    expect(w.emitted('close')).toHaveLength(1);
    w.unmount();
  });
});

describe('TConfirmDialog', () => {
  it('emits confirm when Confirm clicked', async () => {
    const w = mount(TConfirmDialog, {
      props: { open: true, title: 'Revoke?', message: 'Cannot be undone.' },
      attachTo: document.body,
    });
    (document.querySelector('.t-confirm-ok') as HTMLButtonElement).click();
    await w.vm.$nextTick();
    expect(w.emitted('confirm')).toHaveLength(1);
    w.unmount();
  });

  it('emits cancel when Cancel clicked', async () => {
    const w = mount(TConfirmDialog, {
      props: { open: true, title: 'Revoke?' },
      attachTo: document.body,
    });
    (document.querySelector('.t-confirm-cancel') as HTMLButtonElement).click();
    await w.vm.$nextTick();
    expect(w.emitted('cancel')).toHaveLength(1);
    w.unmount();
  });
});
