import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Settings from '../../src/views/Settings.vue';

describe('Settings view', () => {
  it('renders all runtime config fields', () => {
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        settings: {
          settings: {
            parallelism: 10,
            gateway_listen: ':8443',
            gateway_hostname: 'manage.example.com',
            report_server_url: 'https://report.example.com',
            manage_listen: ':8082',
            instance_id: 'abc-123',
            version: '0.1.0',
          },
          loading: false,
          error: '',
        },
      },
    });
    const stubs = {
      // Render the slot so dl/dt/dd show up in the rendered HTML. The
      // default string-stub of 'TPanel' swallows the default slot.
      TPanel: {
        props: ['title'],
        template: '<section class="t-panel-stub" :data-title="title"><slot /></section>',
      },
    };
    const w = mount(Settings, { global: { plugins: [pinia], stubs } });
    expect(w.html()).toContain(':8443');
    expect(w.html()).toContain(':8082');
    expect(w.html()).toContain('manage.example.com');
    expect(w.html()).toContain('https://report.example.com');
    expect(w.html()).toContain('10');
    expect(w.html()).toContain('abc-123');
    expect(w.html()).toContain('0.1.0');
  });
});
