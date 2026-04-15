// Onboarding Phase 1 management UI.
// Minimal hash-router SPA matching the style of the existing report UI
// (vanilla JS, no build step). Consumes /api/v1/manage/*.

(function () {
  // ---------- Auth plumbing ----------
  // Reuse the same JWT storage key ('tritonJWT') as the report UI's
  // app.js so a single sign-on covers both surfaces.
  const TOKEN_KEY = 'tritonJWT';

  function getToken() {
    return localStorage.getItem(TOKEN_KEY) || '';
  }

  function setToken(t) {
    localStorage.setItem(TOKEN_KEY, t);
  }

  function clearToken() {
    localStorage.removeItem(TOKEN_KEY);
  }

  async function authedFetch(path, opts = {}) {
    const headers = Object.assign(
      { 'Content-Type': 'application/json' },
      opts.headers || {},
      { Authorization: 'Bearer ' + getToken() }
    );
    const resp = await fetch(path, Object.assign({}, opts, { headers }));
    if (resp.status === 401) {
      clearToken();
      renderLogin();
      throw new Error('unauthorized');
    }
    return resp;
  }

  function claimsFromToken() {
    const t = getToken();
    if (!t) return null;
    const parts = t.split('.');
    if (parts.length !== 3) return null;
    try {
      return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    } catch (e) {
      return null;
    }
  }

  function currentRole() {
    const c = claimsFromToken();
    return c ? c.role || '' : '';
  }

  // Engineer (org_user) and org_admin can mutate; Officer (org_officer)
  // is view-only. Keep in sync with pkg/server/inventory/routes.go.
  function canMutate() {
    const r = currentRole();
    return r === 'org_admin' || r === 'org_user';
  }

  function isOwner() {
    return currentRole() === 'org_admin';
  }

  // ---------- Router ----------

  const routes = {
    '/dashboard': renderDashboard,
    '/groups': renderGroups,
    '/hosts': renderHosts,
    '/engines': renderEngines,
  };

  function route() {
    if (!getToken()) {
      renderLogin();
      return;
    }
    const path = window.location.hash.replace('#', '') || '/dashboard';
    const h = routes[path] || renderDashboard;
    h(document.getElementById('app'));
  }

  window.addEventListener('hashchange', route);
  window.addEventListener('DOMContentLoaded', () => {
    const logout = document.getElementById('logout');
    if (logout) {
      logout.addEventListener('click', (e) => {
        e.preventDefault();
        clearToken();
        renderLogin();
      });
    }
    route();
  });

  // ---------- Views ----------

  function renderLogin() {
    const app = document.getElementById('app');
    app.innerHTML = `
      <h1>Sign in</h1>
      <form id="login">
        <label>Email <input name="email" type="email" required></label>
        <label>Password <input name="password" type="password" required></label>
        <button>Sign in</button>
      </form>
      <div id="err" class="error"></div>
    `;
    app.querySelector('#login').addEventListener('submit', async (e) => {
      e.preventDefault();
      const body = {
        email: e.target.email.value,
        password: e.target.password.value,
      };
      const resp = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        app.querySelector('#err').textContent = 'Login failed';
        return;
      }
      const data = await resp.json();
      setToken(data.token || data.access_token || data.jwt);
      route();
    });
  }

  async function renderDashboard(el) {
    const role = currentRole();
    el.innerHTML = `
      <h1>Dashboard</h1>
      <p>Signed in as <strong>${escapeHTML(role) || 'unknown'}</strong>.</p>
      <p>Add groups and hosts to get started. Scans will be enabled in a later phase.</p>
    `;
  }

  async function renderGroups(el) {
    el.innerHTML = `
      <h1>Groups</h1>
      <div id="list">loading&hellip;</div>
      ${canMutate() ? `
        <h2>Create group</h2>
        <form id="newgrp">
          <label>Name <input name="name" required></label>
          <label>Description <input name="description"></label>
          <button>Create</button>
        </form>
      ` : ''}
    `;
    try {
      const resp = await authedFetch('/api/v1/manage/groups');
      const groups = await resp.json();
      const list = el.querySelector('#list');
      list.innerHTML = groups && groups.length
        ? '<ul>' + groups.map(g => `<li><strong>${escapeHTML(g.name)}</strong>${g.description ? ' &mdash; ' + escapeHTML(g.description) : ''}</li>`).join('') + '</ul>'
        : '<p><em>No groups yet.</em></p>';
    } catch (e) {
      if (e.message !== 'unauthorized') {
        el.querySelector('#list').textContent = 'Error loading groups.';
      }
      return;
    }
    const form = el.querySelector('#newgrp');
    if (form) {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const body = {
          name: e.target.name.value,
          description: e.target.description.value,
        };
        const resp = await authedFetch('/api/v1/manage/groups', {
          method: 'POST',
          body: JSON.stringify(body),
        });
        if (resp.ok) {
          route();
        } else {
          alert('Failed: ' + resp.status);
        }
      });
    }
  }

  async function renderHosts(el) {
    el.innerHTML = `
      <h1>Hosts</h1>
      <div id="list">loading&hellip;</div>
      ${canMutate() ? `
        <h2>Create host</h2>
        <form id="newhost">
          <label>Group
            <select name="group_id" id="group_select"><option value="">&mdash; select &mdash;</option></select>
          </label>
          <label>Hostname <input name="hostname"></label>
          <label>IP address <input name="address" type="text" placeholder="10.0.0.1"></label>
          <label>OS
            <select name="os">
              <option value="">unknown</option>
              <option>linux</option>
              <option>windows</option>
              <option>macos</option>
              <option>cisco-iosxe</option>
              <option>juniper-junos</option>
            </select>
          </label>
          <label>Mode
            <select name="mode">
              <option>agentless</option>
              <option>agent</option>
            </select>
          </label>
          <button>Create</button>
        </form>
      ` : ''}
    `;
    try {
      const [hostsResp, groupsResp] = await Promise.all([
        authedFetch('/api/v1/manage/hosts'),
        authedFetch('/api/v1/manage/groups'),
      ]);
      const hosts = await hostsResp.json();
      const groups = await groupsResp.json();
      const list = el.querySelector('#list');
      const byGroup = Object.fromEntries((groups || []).map(g => [g.id, g.name]));
      list.innerHTML = hosts && hosts.length
        ? '<table><thead><tr><th>Hostname</th><th>Address</th><th>OS</th><th>Mode</th><th>Group</th></tr></thead><tbody>' +
          hosts.map(h => `<tr>
            <td>${escapeHTML(h.hostname || '—')}</td>
            <td>${escapeHTML(h.address || '—')}</td>
            <td>${escapeHTML(h.os || '—')}</td>
            <td>${escapeHTML(h.mode)}</td>
            <td>${escapeHTML(byGroup[h.group_id] || h.group_id)}</td>
          </tr>`).join('') + '</tbody></table>'
        : '<p><em>No hosts yet.</em></p>';

      const sel = el.querySelector('#group_select');
      if (sel && groups) {
        for (const g of groups) {
          const opt = document.createElement('option');
          opt.value = g.id;
          opt.textContent = g.name;
          sel.appendChild(opt);
        }
      }
    } catch (e) {
      if (e.message !== 'unauthorized') {
        el.querySelector('#list').textContent = 'Error loading hosts.';
      }
      return;
    }

    const form = el.querySelector('#newhost');
    if (form) {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const body = {
          group_id: e.target.group_id.value,
          hostname: e.target.hostname.value,
          address: e.target.address.value,
          os: e.target.os.value,
          mode: e.target.mode.value,
        };
        const resp = await authedFetch('/api/v1/manage/hosts', {
          method: 'POST',
          body: JSON.stringify(body),
        });
        if (resp.ok) {
          route();
        } else {
          alert('Failed: ' + resp.status);
        }
      });
    }
  }

  async function renderEngines(el) {
    el.innerHTML = `
      <h1>Engines</h1>
      <p class="muted">Engines are on-prem daemons that connect back to this portal. Create one, download the bundle, and run it on a host with network access to your target machines.</p>
      <div id="list">loading&hellip;</div>
      ${canMutate() ? `
        <h2>New engine</h2>
        <form id="newengine">
          <label>Label <input name="label" required placeholder="engine-kl-dc"></label>
          <button>Create and download bundle</button>
        </form>
        <p class="muted small">The bundle is one-time: once the engine enrolls, the bundle can no longer be re-downloaded. Keep it secure in transit.</p>
      ` : ''}
    `;

    try {
      const resp = await authedFetch('/api/v1/manage/engines/');
      const engines = await resp.json();
      const list = el.querySelector('#list');
      list.innerHTML = engines && engines.length
        ? renderEnginesTable(engines)
        : '<p><em>No engines yet. Create one to get started.</em></p>';

      if (isOwner()) {
        list.querySelectorAll('button.revoke').forEach(btn => {
          btn.addEventListener('click', async () => {
            if (!confirm('Revoke this engine? It will no longer be able to connect.')) return;
            const id = btn.dataset.id;
            const r = await authedFetch(`/api/v1/manage/engines/${id}/revoke`, { method: 'POST' });
            if (r.ok) route();
            else alert('Revoke failed: ' + r.status);
          });
        });
      }
    } catch (e) {
      if (e.message !== 'unauthorized') {
        el.querySelector('#list').textContent = 'Error loading engines.';
      }
      return;
    }

    const form = el.querySelector('#newengine');
    if (form) {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const label = e.target.label.value.trim();
        const resp = await authedFetch('/api/v1/manage/engines/', {
          method: 'POST',
          body: JSON.stringify({ label }),
        });
        if (!resp.ok) {
          alert('Create failed: ' + resp.status);
          return;
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `engine-${label}.tar.gz`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setTimeout(route, 300);
      });
    }
  }

  function renderEnginesTable(engines) {
    const rows = engines.map(e => {
      const statusBadge = `<span class="badge badge-${e.status}">${escapeHTML(e.status)}</span>`;
      const lastPoll = e.last_poll_at ? timeAgo(e.last_poll_at) : '—';
      const firstSeen = e.first_seen_at ? timeAgo(e.first_seen_at) : '<em>never</em>';
      const ip = e.public_ip || '—';
      const actions = isOwner() && e.status !== 'revoked'
        ? `<button class="revoke" data-id="${escapeHTML(e.id)}">Revoke</button>`
        : '';
      return `<tr>
        <td>${escapeHTML(e.label)}</td>
        <td>${statusBadge}</td>
        <td>${escapeHTML(ip)}</td>
        <td>${firstSeen}</td>
        <td>${lastPoll}</td>
        <td>${actions}</td>
      </tr>`;
    }).join('');
    return `<table>
      <thead><tr><th>Label</th><th>Status</th><th>Public IP</th><th>First seen</th><th>Last poll</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  }

  function timeAgo(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    const diffMs = Date.now() - d.getTime();
    const sec = Math.floor(diffMs / 1000);
    if (sec < 60) return sec + 's ago';
    const min = Math.floor(sec / 60);
    if (min < 60) return min + 'm ago';
    const hr = Math.floor(min / 60);
    if (hr < 24) return hr + 'h ago';
    return Math.floor(hr / 24) + 'd ago';
  }

  function escapeHTML(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }
})();
