import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';

import ChangePassword from '../../src/views/ChangePassword.vue';

function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/dashboard', component: { template: '<div>d</div>' } },
      { path: '/auth/change-password', component: ChangePassword },
    ],
  });
}

describe('ChangePassword.vue', () => {
  it('renders three password inputs', () => {
    const w = mount(ChangePassword, {
      global: { plugins: [createTestingPinia({ createSpy: vi.fn }), makeRouter()] },
    });
    const inputs = w.findAll('input[type="password"]');
    expect(inputs.length).toBe(3);
  });

  it('disables submit until validations pass', async () => {
    const w = mount(ChangePassword, {
      global: { plugins: [createTestingPinia({ createSpy: vi.fn }), makeRouter()] },
    });
    const submit = w.find('button[type="submit"]');
    expect(submit.attributes('disabled')).toBeDefined();

    const [cur, next, conf] = w.findAll('input[type="password"]');
    await cur.setValue('OldPass1234!');
    await next.setValue('NewSecret9876!');
    await conf.setValue('NewSecret9876!');
    await w.vm.$nextTick();
    expect(submit.attributes('disabled')).toBeUndefined();
  });
});
