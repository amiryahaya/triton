import { describe, it, expect, afterEach } from 'vitest';
import { mount } from '@vue/test-utils';
import TAppSwitcher, { type AppEntry } from '../src/shell/TAppSwitcher.vue';

const apps: AppEntry[] = [
  { id: 'license', name: 'Licence', subtitle: 'Vendor ops',
    url: 'http://localhost:8081', accent: '#a78bfa' },
  { id: 'report',  name: 'Report',  subtitle: 'Security',
    url: 'http://localhost:8080', accent: '#22d3ee' },
  { id: 'manage',  name: 'Manage',  subtitle: 'Network',
    url: null, accent: '#a3e635' },
];

describe('TAppSwitcher', () => {
  afterEach(() => { document.body.innerHTML = ''; });

  it('is closed by default', () => {
    const w = mount(TAppSwitcher, {
      props: { apps, currentId: 'report' },
      attachTo: document.body,
    });
    expect(document.querySelector('.t-app-menu')).toBeNull();
    w.unmount();
  });

  it('opens on button click', async () => {
    const w = mount(TAppSwitcher, {
      props: { apps, currentId: 'report' },
      attachTo: document.body,
    });
    await w.find('.t-app-trigger').trigger('click');
    expect(document.querySelector('.t-app-menu')).not.toBeNull();
    w.unmount();
  });

  it('greys out apps with null url', async () => {
    const w = mount(TAppSwitcher, {
      props: { apps, currentId: 'report' },
      attachTo: document.body,
    });
    await w.find('.t-app-trigger').trigger('click');
    const tiles = document.querySelectorAll('.t-app-tile');
    const manage = Array.from(tiles).find((t) => t.textContent?.includes('Manage'));
    expect(manage?.classList.contains('is-disabled')).toBe(true);
    w.unmount();
  });

  it('marks current app', async () => {
    const w = mount(TAppSwitcher, {
      props: { apps, currentId: 'report' },
      attachTo: document.body,
    });
    await w.find('.t-app-trigger').trigger('click');
    const current = document.querySelector('.t-app-tile.is-current');
    expect(current?.textContent).toContain('Report');
    w.unmount();
  });
});
