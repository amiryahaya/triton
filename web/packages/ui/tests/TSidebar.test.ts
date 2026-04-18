import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TSidebar, { type NavSection } from '../src/shell/TSidebar.vue';

const nav: NavSection[] = [
  { items: [
    { href: '#/', label: 'Dashboard' },
    { href: '#/orgs', label: 'Organisations' },
  ] },
  { label: 'Admin', items: [{ href: '#/audit', label: 'Audit log' }] },
];

describe('TSidebar', () => {
  it('renders items in each section', () => {
    const w = mount(TSidebar, {
      props: { nav, portalTitle: 'Triton', portalSubtitle: 'Licence', currentHref: '#/' },
    });
    expect(w.findAll('.t-nav-item')).toHaveLength(3);
  });

  it('marks current item active', () => {
    const w = mount(TSidebar, {
      props: { nav, portalTitle: 'Triton', portalSubtitle: 'Licence', currentHref: '#/orgs' },
    });
    const active = w.findAll('.t-nav-item.is-active');
    expect(active).toHaveLength(1);
    expect(active[0]!.text()).toContain('Organisations');
  });

  it('renders section labels', () => {
    const w = mount(TSidebar, {
      props: { nav, portalTitle: 'Triton', portalSubtitle: 'Licence', currentHref: '#/' },
    });
    expect(w.text()).toContain('Admin');
  });

  it('renders footer slot', () => {
    const w = mount(TSidebar, {
      props: { nav, portalTitle: 'Triton', portalSubtitle: 'Licence', currentHref: '#/' },
      slots: { footer: '<div class="foot">me</div>' },
    });
    expect(w.find('.foot').exists()).toBe(true);
  });
});
