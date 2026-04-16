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
    '/hosts/import': renderCSVImport,
    '/engines': renderEngines,
    '/discoveries': renderDiscoveries,
    '/discoveries/new': renderNewDiscovery,
    '/credentials': renderCredentials,
    '/credentials/new': renderNewCredential,
    '/scan-jobs': renderScanJobs,
    '/scan-jobs/new': renderNewScanJob,
    '/fleet': renderFleet,
    '/fleet/push': renderPushAgent,
    '/audit': renderAudit,
  };

  function setSidebarVisible(visible) {
    var sidebar = document.querySelector('.sidebar');
    if (sidebar) sidebar.style.display = visible ? '' : 'none';
  }

  function route() {
    if (!getToken()) {
      setSidebarVisible(false);
      renderLogin();
      return;
    }
    setSidebarVisible(true);
    const rawPath = window.location.hash.replace('#', '') || '/dashboard';
    // Strip query string (e.g. #/scan-jobs/new?group_id=<uuid>) before
    // matching static routes or UUID-suffixed dynamic routes.
    const path = rawPath.split('?')[0];
    const discMatch = path.match(/^\/discoveries\/([0-9a-f-]{36})$/);
    if (discMatch) {
      renderDiscoveryDetail(document.getElementById('app'), discMatch[1]);
      return;
    }
    const credTestMatch = path.match(/^\/credentials\/tests\/([0-9a-f-]{36})$/);
    if (credTestMatch) {
      renderCredentialTestDetail(document.getElementById('app'), credTestMatch[1]);
      return;
    }
    const credMatch = path.match(/^\/credentials\/([0-9a-f-]{36})$/);
    if (credMatch) {
      renderCredentialDetail(document.getElementById('app'), credMatch[1]);
      return;
    }
    const scanJobMatch = path.match(/^\/scan-jobs\/([0-9a-f-]{36})$/);
    if (scanJobMatch) {
      renderScanJobDetail(document.getElementById('app'), scanJobMatch[1]);
      return;
    }
    const pushJobMatch = path.match(/^\/fleet\/push\/([0-9a-f-]{36})$/);
    if (pushJobMatch) {
      renderPushJobDetail(document.getElementById('app'), pushJobMatch[1]);
      return;
    }
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
      <div id="metrics"></div>
      <p class="muted">Add groups and hosts to get started. Scans will produce findings visible in Reports.</p>
    `;
    try {
      const resp = await authedFetch('/api/v1/manage/onboarding-metrics');
      if (resp.ok) {
        const m = await resp.json();
        const metricsEl = el.querySelector('#metrics');
        if (m.minutes_to_first_scan != null) {
          const mins = Math.round(m.minutes_to_first_scan);
          const color = mins <= 20 ? 'var(--accent)' : mins <= 45 ? '#92400e' : 'var(--error)';
          metricsEl.innerHTML = `
            <div class="metric-card">
              <span class="metric-value" style="color:${color}">${mins} min</span>
              <span class="metric-label">Time to first scan</span>
            </div>
          `;
        } else {
          const steps = [
            { label: 'Signed up', done: !!m.t_signup },
            { label: 'Engine enrolled', done: !!m.t_engine },
            { label: 'Hosts added', done: !!m.t_hosts },
            { label: 'Credential created', done: !!m.t_creds },
            { label: 'Scan triggered', done: !!m.t_scan },
            { label: 'Results received', done: !!m.t_results },
          ];
          if (steps.some(s => s.done)) {
            metricsEl.innerHTML = `
              <h2>Onboarding progress</h2>
              <ul class="journey-steps">${steps.map(s =>
                `<li class="${s.done ? 'done' : 'pending'}">${s.done ? '&#10003;' : '&#9675;'} ${escapeHTML(s.label)}</li>`
              ).join('')}</ul>
            `;
          }
        }
      }
    } catch (e) {
      // Silently degrade — metrics are advisory
    }
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
      if (!groups || !groups.length) {
        list.innerHTML = '<p><em>No groups yet.</em></p>';
      } else {
        const showActions = canMutate();
        const headActions = showActions ? '<th></th>' : '';
        list.innerHTML = '<table><thead><tr><th>Name</th><th>Description</th>' + headActions + '</tr></thead><tbody>' +
          groups.map(g => {
            const actions = showActions
              ? `<td><a href="#/scan-jobs/new?group_id=${escapeHTML(g.id)}" class="button">Scan now</a> <a href="#/fleet/push?group_id=${escapeHTML(g.id)}" class="button">Push agent</a></td>`
              : '';
            return `<tr>
              <td><strong>${escapeHTML(g.name)}</strong></td>
              <td>${g.description ? escapeHTML(g.description) : '<span class="muted">—</span>'}</td>
              ${actions}
            </tr>`;
          }).join('') + '</tbody></table>';
      }
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
        <p><a href="#/hosts/import" class="nav-link-inline">Import from CSV &rarr;</a></p>
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

  // ---------- CSV Import (Task 10) ----------

  async function renderCSVImport(el) {
    if (!canMutate()) {
      el.innerHTML = '<h1>Import hosts from CSV</h1><p>Only Engineers and Owners can import hosts.</p>';
      return;
    }
    el.innerHTML = `
      <h1>Import hosts from CSV</h1>
      <p class="muted">Expected columns: <code>hostname,address,os,mode,tags</code>. The <code>tags</code> column is semicolon-separated key=value pairs, e.g. <code>env=prod;team=platform</code>. Missing columns are treated as empty.</p>
      <form id="csvForm">
        <label>Target group
          <select name="group_id" id="csv_group" required>
            <option value="">&mdash; choose group &mdash;</option>
          </select>
        </label>
        <label>CSV file
          <input type="file" id="csvFile" accept=".csv,text/csv" required>
        </label>
      </form>
      <div id="csv_preview"></div>
      <p><a href="#/hosts">&larr; Back to hosts</a></p>
    `;

    const sel = el.querySelector('#csv_group');
    try {
      const resp = await authedFetch('/api/v1/manage/groups/');
      const groups = await resp.json();
      for (const g of groups || []) {
        const opt = document.createElement('option');
        opt.value = g.id;
        opt.textContent = g.name;
        sel.appendChild(opt);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('groups load', e);
    }

    // 5MB ~= 50k simple rows. The server caps at 10k rows, so anything
    // bigger than this client-side limit would be rejected anyway and
    // we save the tab from freezing on FileReader.text() of a huge file.
    const MAX_CSV_BYTES = 5 * 1024 * 1024;

    el.querySelector('#csvFile').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > MAX_CSV_BYTES) {
        el.querySelector('#csv_preview').innerHTML =
          `<p class="error">File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Max ${MAX_CSV_BYTES / 1024 / 1024} MB.</p>`;
        return;
      }
      try {
        const text = await file.text();
        const rows = parseCSV(text);
        renderCSVPreview(el.querySelector('#csv_preview'), rows, () => sel.value);
      } catch (err) {
        el.querySelector('#csv_preview').innerHTML = `<p class="error">Parse failed: ${escapeHTML(err.message)}</p>`;
      }
    });
  }

  function parseCSV(text) {
    // Reject files with newlines inside quoted fields. A naive
    // line-split tokenizer would desync row boundaries, mapping fields
    // to the wrong columns silently. A full quote-aware state machine
    // is more code than this path deserves; operators exporting from
    // spreadsheets rarely need embedded newlines, and a clear rejection
    // beats a silent corrupt import.
    if (hasQuotedNewline(text)) {
      throw new Error('CSV contains newlines inside quoted fields — not supported. Re-export without embedded line breaks.');
    }
    const lines = text.split(/\r?\n/).filter(l => l.length > 0);
    if (lines.length < 1) throw new Error('file is empty');
    const header = splitCSVLine(lines[0]).map(h => h.toLowerCase().trim());
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
      const fields = splitCSVLine(lines[i]);
      const row = {};
      for (let j = 0; j < header.length; j++) {
        row[header[j]] = (fields[j] || '').trim();
      }
      rows.push(row);
    }
    return rows;
  }

  // hasQuotedNewline walks the text tracking quote state so that an
  // escaped "" pair inside a quoted field doesn't flip state twice (it
  // represents a literal quote, not a close-then-open). Returns true on
  // the first raw \n or \r encountered while inside quotes.
  function hasQuotedNewline(text) {
    let inQuotes = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (ch === '"') {
        if (inQuotes && text[i + 1] === '"') { i++; continue; }
        inQuotes = !inQuotes;
      } else if ((ch === '\n' || ch === '\r') && inQuotes) {
        return true;
      }
    }
    return false;
  }

  function splitCSVLine(line) {
    const out = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') { cur += '"'; i++; }
        else inQuotes = !inQuotes;
      } else if (ch === ',' && !inQuotes) {
        out.push(cur); cur = '';
      } else {
        cur += ch;
      }
    }
    out.push(cur);
    return out;
  }

  function mapCSVRows(rows) {
    return rows.map(r => ({
      hostname: r.hostname || '',
      address: r.address || r.ip || '',
      os: r.os || '',
      mode: r.mode || 'agentless',
      tags: (r.tags || '').split(';').map(kv => kv.trim()).filter(Boolean).map(kv => {
        const eq = kv.indexOf('=');
        if (eq < 0) return { key: kv, value: '' };
        return { key: kv.slice(0, eq), value: kv.slice(eq + 1) };
      }),
    }));
  }

  function renderCSVPreview(el, rows, getGroupId) {
    const mapped = mapCSVRows(rows);
    const preview = mapped.slice(0, 10);
    el.innerHTML = `
      <h2>Preview</h2>
      <p>${mapped.length} row${mapped.length === 1 ? '' : 's'} in file.</p>
      <table>
        <thead><tr><th>Hostname</th><th>Address</th><th>OS</th><th>Mode</th><th>Tags</th></tr></thead>
        <tbody>${preview.map(r => `<tr>
          <td>${escapeHTML(r.hostname)}</td>
          <td>${escapeHTML(r.address)}</td>
          <td>${escapeHTML(r.os)}</td>
          <td>${escapeHTML(r.mode)}</td>
          <td>${r.tags.map(t => escapeHTML(t.key) + '=' + escapeHTML(t.value)).join(', ')}</td>
        </tr>`).join('')}</tbody>
      </table>
      ${mapped.length > 10 ? `<p class="muted">Showing first 10 of ${mapped.length}.</p>` : ''}
      <div class="button-row">
        <button id="dryRun">Dry-run</button>
        <button id="commit" class="primary">Import ${mapped.length} host${mapped.length === 1 ? '' : 's'}</button>
      </div>
      <div id="csv_result"></div>
    `;
    el.querySelector('#dryRun').addEventListener('click', () =>
      doImport(mapped, getGroupId(), true, el.querySelector('#csv_result'))
    );
    el.querySelector('#commit').addEventListener('click', () =>
      doImport(mapped, getGroupId(), false, el.querySelector('#csv_result'))
    );
  }

  async function doImport(rows, groupId, dryRun, resultEl) {
    if (!groupId) { resultEl.innerHTML = '<p class="error">Choose a group first.</p>'; return; }
    if (rows.length === 0) { resultEl.innerHTML = '<p class="error">No rows to import.</p>'; return; }
    if (rows.length > 10000) { resultEl.innerHTML = '<p class="error">Max 10,000 rows per import.</p>'; return; }
    resultEl.innerHTML = '<p class="muted">Running&hellip;</p>';
    try {
      const resp = await authedFetch('/api/v1/manage/hosts/import', {
        method: 'POST',
        body: JSON.stringify({ group_id: groupId, rows, dry_run: dryRun }),
      });
      if (!resp.ok) {
        resultEl.innerHTML = `<p class="error">Import failed: HTTP ${resp.status}</p>`;
        return;
      }
      const data = await resp.json();
      const label = dryRun ? '(dry-run &mdash; no rows inserted)' : '(committed)';
      const errorList = data.errors && data.errors.length
        ? `<h3>Errors (${data.errors.length})</h3><ul>${data.errors.map(e => `<li>Row ${e.row}: ${escapeHTML(e.error)}</li>`).join('')}</ul>`
        : '';
      resultEl.innerHTML = `
        <h3>${label}</h3>
        <p>Accepted: <strong>${data.accepted}</strong>, Rejected: <strong>${data.rejected}</strong>, Duplicates: <strong>${data.duplicates}</strong></p>
        ${errorList}
        ${!dryRun && data.accepted > 0 ? '<p><a href="#/hosts">View hosts &rarr;</a></p>' : ''}
      `;
    } catch (e) {
      resultEl.innerHTML = `<p class="error">Request failed: ${escapeHTML(e.message)}</p>`;
    }
  }

  // ---------- Discoveries (Task 11) ----------

  async function renderDiscoveries(el) {
    el.innerHTML = `
      <h1>Network Discovery</h1>
      <p class="muted">Scan your network ranges to find hosts you haven't inventoried yet. Each discovery job runs on an engine and produces a list of candidates you can promote into a group.</p>
      ${canMutate() ? '<p><a href="#/discoveries/new" class="button">New discovery</a></p>' : ''}
      <div id="list">loading&hellip;</div>
    `;
    try {
      const resp = await authedFetch('/api/v1/manage/discoveries/');
      const jobs = await resp.json();
      const list = el.querySelector('#list');
      if (!jobs || jobs.length === 0) {
        list.innerHTML = '<p><em>No discovery jobs yet.</em></p>';
        return;
      }
      list.innerHTML = `
        <table>
          <thead><tr><th>Requested</th><th>CIDRs</th><th>Ports</th><th>Status</th><th>Candidates</th><th></th></tr></thead>
          <tbody>${jobs.map(j => `<tr>
            <td>${timeAgo(j.requested_at)}</td>
            <td>${escapeHTML((j.cidrs || []).join(', '))}</td>
            <td>${(j.ports || []).join(', ')}</td>
            <td><span class="badge badge-${j.status}">${j.status}</span></td>
            <td>${j.candidate_count}</td>
            <td><a href="#/discoveries/${j.id}">View &rarr;</a></td>
          </tr>`).join('')}</tbody>
        </table>
      `;
    } catch (e) {
      if (e.message !== 'unauthorized') el.querySelector('#list').textContent = 'Error loading discoveries.';
    }
  }

  async function renderNewDiscovery(el) {
    if (!canMutate()) { el.innerHTML = '<h1>New discovery</h1><p>Only Engineers and Owners can start discoveries.</p>'; return; }
    el.innerHTML = `
      <h1>New discovery</h1>
      <form id="newDisc">
        <label>Engine
          <select name="engine_id" id="engine_sel" required>
            <option value="">&mdash; choose engine &mdash;</option>
          </select>
        </label>
        <label>CIDRs (one per line)
          <textarea name="cidrs" rows="4" required placeholder="10.0.0.0/24&#10;192.168.1.0/24"></textarea>
        </label>
        <fieldset style="border:1px solid var(--border,#ccc);padding:.75rem;border-radius:6px;margin:.5rem 0">
          <legend style="font-weight:600;padding:0 .25rem">Probe type</legend>
          <label style="display:block;margin-bottom:.25rem"><input type="radio" name="probe_type" value="ping" checked> Ping sweep (find all live hosts)</label>
          <label style="display:block"><input type="radio" name="probe_type" value="tcp"> TCP port scan (find hosts + open ports)</label>
        </fieldset>
        <label id="ports_label" style="display:none">Ports (comma-separated, defaults to 22,80,443,3389,5985)
          <input name="ports" placeholder="22,80,443,3389,5985">
        </label>
        <div class="button-row">
          <a href="#/discoveries" class="button">Cancel</a>
          <button class="primary">Start discovery</button>
        </div>
        <div id="new_err"></div>
      </form>
    `;

    // Toggle ports input visibility based on probe type selection.
    const portsLabel = el.querySelector('#ports_label');
    el.querySelectorAll('input[name="probe_type"]').forEach(radio => {
      radio.addEventListener('change', () => {
        portsLabel.style.display = radio.value === 'tcp' && radio.checked ? '' : 'none';
      });
    });

    const sel = el.querySelector('#engine_sel');
    try {
      const resp = await authedFetch('/api/v1/manage/engines/');
      const engines = await resp.json();
      for (const e of engines || []) {
        if (e.status === 'revoked') continue;
        const opt = document.createElement('option');
        opt.value = e.id;
        opt.textContent = `${e.label} (${e.status})`;
        sel.appendChild(opt);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('engines load', e);
    }

    el.querySelector('#newDisc').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = ev.target;
      const cidrs = f.cidrs.value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      const probeType = f.probe_type.value;
      const payload = { engine_id: f.engine_id.value, cidrs };
      if (probeType === 'ping') {
        payload.ports = []; // explicitly empty = ping sweep
      } else {
        const portsStr = f.ports.value.trim();
        if (portsStr) {
          payload.ports = portsStr.split(',').map(s => parseInt(s.trim(), 10)).filter(n => Number.isInteger(n) && n >= 1 && n <= 65535);
        }
        // omit ports entirely → server applies default [22,80,443,3389,5985]
      }
      try {
        const resp = await authedFetch('/api/v1/manage/discoveries/', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        if (!resp.ok) {
          const txt = await resp.text();
          el.querySelector('#new_err').innerHTML = `<p class="error">${escapeHTML(txt || ('HTTP ' + resp.status))}</p>`;
          return;
        }
        const job = await resp.json();
        window.location.hash = '#/discoveries/' + job.id;
      } catch (e) {
        el.querySelector('#new_err').innerHTML = `<p class="error">${escapeHTML(e.message)}</p>`;
      }
    });
  }

  async function renderDiscoveryDetail(el, jobID) {
    el.innerHTML = `<p>loading&hellip;</p>`;
    try {
      const resp = await authedFetch('/api/v1/manage/discoveries/' + jobID);
      if (!resp.ok) { el.innerHTML = '<p>Not found.</p>'; return; }
      const data = await resp.json();
      const job = data.job;
      const candidates = data.candidates || [];

      const running = job.status === 'queued' || job.status === 'claimed' || job.status === 'running';
      const canCancel = canMutate() && job.status === 'queued';
      const canPromote = canMutate() && candidates.some(c => !c.promoted);

      el.innerHTML = `
        <p><a href="#/discoveries">&larr; Back to discoveries</a></p>
        <h1>Discovery job</h1>
        <dl class="kv">
          <dt>Status</dt><dd><span class="badge badge-${job.status}">${job.status}</span></dd>
          <dt>CIDRs</dt><dd>${escapeHTML((job.cidrs || []).join(', '))}</dd>
          <dt>Ports</dt><dd>${(job.ports || []).join(', ')}</dd>
          <dt>Requested</dt><dd>${timeAgo(job.requested_at)}</dd>
          ${job.claimed_at ? `<dt>Claimed</dt><dd>${timeAgo(job.claimed_at)}</dd>` : ''}
          ${job.completed_at ? `<dt>Completed</dt><dd>${timeAgo(job.completed_at)}</dd>` : ''}
          ${job.error ? `<dt>Error</dt><dd class="error">${escapeHTML(job.error)}</dd>` : ''}
        </dl>
        ${canCancel ? '<button id="cancelBtn" class="danger">Cancel job</button>' : ''}

        <h2>Candidates (${candidates.length})</h2>
        ${candidates.length === 0
          ? (running ? '<p class="muted">Scan in progress &mdash; results will appear here.</p>' : '<p><em>No hosts discovered.</em></p>')
          : renderCandidatesBlock(candidates)
        }
        <div id="promote_result"></div>
      `;

      if (canCancel) {
        el.querySelector('#cancelBtn').addEventListener('click', async () => {
          if (!confirm('Cancel this discovery job?')) return;
          const r = await authedFetch('/api/v1/manage/discoveries/' + jobID + '/cancel', { method: 'POST' });
          if (r.ok) route(); else alert('Cancel failed: HTTP ' + r.status);
        });
      }

      if (canPromote) {
        el.querySelector('#promoteForm')?.addEventListener('submit', (ev) => {
          ev.preventDefault();
          const f = ev.target;
          const ids = Array.from(f.querySelectorAll('input[name="cand"]:checked')).map(i => i.value);
          const groupId = f.group_id.value;
          if (ids.length === 0) { alert('Select at least one candidate.'); return; }
          if (!groupId) { alert('Choose a group.'); return; }
          promoteCandidates(jobID, ids, groupId, el.querySelector('#promote_result'));
        });

        authedFetch('/api/v1/manage/groups/').then(r => r.json()).then(groups => {
          const sel = el.querySelector('#promote_group');
          for (const g of groups || []) {
            const opt = document.createElement('option');
            opt.value = g.id;
            opt.textContent = g.name;
            sel.appendChild(opt);
          }
        }).catch(() => {});
      }

      if (running) {
        setTimeout(() => { if (window.location.hash === '#/discoveries/' + jobID) route(); }, 5000);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') el.innerHTML = `<p>Error: ${escapeHTML(e.message)}</p>`;
    }
  }

  function renderCandidatesBlock(candidates) {
    const rows = candidates.map(c => `<tr>
      <td><input type="checkbox" name="cand" value="${c.id}" ${c.promoted ? 'disabled' : ''}></td>
      <td>${escapeHTML(c.address)}${c.promoted ? ' <span class="badge badge-enrolled">promoted</span>' : ''}</td>
      <td>${escapeHTML(c.hostname || '')}</td>
      <td>${(c.open_ports || []).join(', ')}</td>
      <td>${timeAgo(c.detected_at)}</td>
    </tr>`).join('');
    return `
      <form id="promoteForm">
        <table>
          <thead><tr><th></th><th>Address</th><th>Hostname</th><th>Open ports</th><th>Detected</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        <label>Promote selected to group
          <select name="group_id" id="promote_group">
            <option value="">&mdash; choose group &mdash;</option>
          </select>
        </label>
        <button class="primary">Promote to hosts</button>
      </form>
    `;
  }

  async function promoteCandidates(jobID, ids, groupId, resultEl) {
    resultEl.innerHTML = '<p class="muted">Promoting&hellip;</p>';
    try {
      const resp = await authedFetch('/api/v1/manage/discoveries/' + jobID + '/promote', {
        method: 'POST',
        body: JSON.stringify({ candidate_ids: ids, group_id: groupId }),
      });
      if (!resp.ok) {
        const txt = await resp.text();
        resultEl.innerHTML = `<p class="error">${escapeHTML(txt || ('HTTP ' + resp.status))}</p>`;
        return;
      }
      const data = await resp.json();
      const errs = data.errors && data.errors.length
        ? `<ul>${data.errors.map(e => `<li>${escapeHTML(e.candidate_id)}: ${escapeHTML(e.error)}</li>`).join('')}</ul>`
        : '';
      resultEl.innerHTML = `<p>Promoted: <strong>${data.promoted || 0}</strong>, Failed: <strong>${data.failed || 0}</strong></p>${errs}`;
      setTimeout(route, 1000);
    } catch (e) {
      resultEl.innerHTML = `<p class="error">${escapeHTML(e.message)}</p>`;
    }
  }

  // ---------- Credentials (Task 11) ----------

  async function renderCredentials(el) {
    el.innerHTML = `
      <h1>Credential Profiles</h1>
      <p class="muted">Credential profiles bind secrets to host matchers. Secrets are encrypted in your browser to the engine's public key — the portal never sees plaintext.</p>
      ${canMutate() ? '<p><a href="#/credentials/new" class="button primary">New credential profile</a></p>' : ''}
      <div id="list">loading&hellip;</div>
    `;
    try {
      const resp = await authedFetch('/api/v1/manage/credentials/');
      const profiles = await resp.json();
      const list = el.querySelector('#list');
      if (!profiles || profiles.length === 0) {
        list.innerHTML = '<p><em>No credential profiles yet.</em></p>';
        return;
      }
      list.innerHTML = `
        <table>
          <thead><tr><th>Name</th><th>Auth type</th><th>Matcher summary</th><th>Last tested</th><th></th></tr></thead>
          <tbody>${profiles.map(p => `<tr>
            <td>${escapeHTML(p.name)}</td>
            <td><span class="badge">${escapeHTML(p.auth_type)}</span></td>
            <td>${escapeHTML(summarizeMatcher(p.matcher || {}))}</td>
            <td>${p.last_tested_at ? timeAgo(p.last_tested_at) : '<em>never</em>'}</td>
            <td><a href="#/credentials/${p.id}">View &rarr;</a></td>
          </tr>`).join('')}</tbody>
        </table>
      `;
    } catch (e) {
      if (e.message !== 'unauthorized') el.querySelector('#list').textContent = 'Error loading credentials.';
    }
  }

  function summarizeMatcher(m) {
    const parts = [];
    if (m.group_ids && m.group_ids.length) parts.push(`groups:${m.group_ids.length}`);
    if (m.os) parts.push(`os:${m.os}`);
    if (m.cidr) parts.push(`cidr:${m.cidr}`);
    if (m.tags) {
      const n = Object.keys(m.tags).length;
      if (n > 0) parts.push(`tags:${n}`);
    }
    return parts.length ? parts.join(', ') : 'any host';
  }

  function parseTagsTextarea(text) {
    const out = {};
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const eq = trimmed.indexOf('=');
      if (eq < 0) continue;
      out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
    }
    return out;
  }

  async function renderNewCredential(el) {
    if (!canMutate()) {
      el.innerHTML = '<h1>New credential</h1><p>Only Engineers and Owners can create credential profiles.</p>';
      return;
    }
    el.innerHTML = `
      <p><a href="#/credentials">&larr; Back to credentials</a></p>
      <h1>New credential profile</h1>
      <p class="muted">The secret is encrypted in your browser to the engine's public key before it leaves this page. The portal stores only the sealed ciphertext.</p>
      <form id="newCred">
        <label>Name <input name="name" required placeholder="prod-linux-ssh"></label>
        <div class="cred-field-group">
          <label>Auth type
            <select name="auth_type" id="auth_type" required>
              <option value="ssh-password">ssh-password</option>
              <option value="ssh-key">ssh-key</option>
              <option value="winrm-password">winrm-password</option>
              <option value="bootstrap-admin">bootstrap-admin</option>
            </select>
          </label>
          <label>Engine
            <select name="engine_id" id="engine_sel" required>
              <option value="">&mdash; choose engine &mdash;</option>
            </select>
          </label>
        </div>

        <h2>Matcher</h2>
        <p class="muted">Leave all fields empty to match every host. Combinations are AND'd together.</p>
        <label>Groups (hold Ctrl/Cmd to multi-select)
          <select name="group_ids" id="group_sel" multiple size="4"></select>
        </label>
        <div class="cred-field-group">
          <label>OS
            <select name="os">
              <option value="">(any)</option>
              <option value="linux">linux</option>
              <option value="windows">windows</option>
              <option value="macos">macos</option>
              <option value="cisco-iosxe">cisco-iosxe</option>
              <option value="juniper-junos">juniper-junos</option>
            </select>
          </label>
          <label>CIDR <input name="cidr" placeholder="10.0.0.0/24"></label>
        </div>
        <label>Tags (one <code>key=value</code> per line)
          <textarea name="tags" rows="3" placeholder="env=prod&#10;team=platform"></textarea>
        </label>

        <h2>Secret</h2>
        <label>Username <input name="username" id="f_username" required></label>
        <div class="conditional show" id="field_password">
          <label>Password <input name="password" type="password"></label>
        </div>
        <div class="conditional" id="field_key">
          <label>Private key (PEM)
            <textarea name="private_key" class="cred-key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."></textarea>
          </label>
          <label>Passphrase (optional) <input name="passphrase" type="password"></label>
        </div>

        <div class="button-row">
          <a href="#/credentials" class="button">Cancel</a>
          <button class="primary">Encrypt and save</button>
        </div>
        <div id="new_err"></div>
      </form>
    `;

    // Populate engines + groups in parallel.
    try {
      const [engResp, grpResp] = await Promise.all([
        authedFetch('/api/v1/manage/engines/'),
        authedFetch('/api/v1/manage/groups/'),
      ]);
      const engines = await engResp.json();
      const groups = await grpResp.json();
      const engSel = el.querySelector('#engine_sel');
      for (const e of engines || []) {
        if (e.status === 'revoked') continue;
        const opt = document.createElement('option');
        opt.value = e.id;
        opt.textContent = `${e.label} (${e.status})`;
        engSel.appendChild(opt);
      }
      const grpSel = el.querySelector('#group_sel');
      for (const g of groups || []) {
        const opt = document.createElement('option');
        opt.value = g.id;
        opt.textContent = g.name;
        grpSel.appendChild(opt);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('cred form load', e);
    }

    // Toggle secret-fields visibility based on auth_type.
    const authSel = el.querySelector('#auth_type');
    const fieldPassword = el.querySelector('#field_password');
    const fieldKey = el.querySelector('#field_key');
    function syncSecretFields() {
      const t = authSel.value;
      if (t === 'ssh-key') {
        fieldPassword.classList.remove('show');
        fieldKey.classList.add('show');
      } else {
        fieldPassword.classList.add('show');
        fieldKey.classList.remove('show');
      }
    }
    authSel.addEventListener('change', syncSecretFields);
    syncSecretFields();

    el.querySelector('#newCred').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = ev.target;
      const errEl = el.querySelector('#new_err');
      errEl.innerHTML = '';

      const name = f.name.value.trim();
      const authType = f.auth_type.value;
      const engineID = f.engine_id.value;
      if (!name || !authType || !engineID) {
        errEl.innerHTML = '<p class="error">Name, auth type, and engine are required.</p>';
        return;
      }

      // Build matcher — omit empty branches so the server sees an explicit
      // "no constraint" instead of zero-length arrays that might trip
      // validation down the line.
      const matcher = {};
      const groupIDs = Array.from(f.group_ids.selectedOptions).map(o => o.value).filter(Boolean);
      if (groupIDs.length) matcher.group_ids = groupIDs;
      if (f.os.value) matcher.os = f.os.value;
      if (f.cidr.value.trim()) matcher.cidr = f.cidr.value.trim();
      const tags = parseTagsTextarea(f.tags.value);
      if (Object.keys(tags).length) matcher.tags = tags;

      // Build secret JSON.
      const username = f.username.value.trim();
      if (!username) {
        errEl.innerHTML = '<p class="error">Username is required.</p>';
        return;
      }
      let secret;
      if (authType === 'ssh-key') {
        const pk = f.private_key.value;
        if (!pk || pk.trim().length === 0) {
          errEl.innerHTML = '<p class="error">Private key is required for ssh-key.</p>';
          return;
        }
        secret = { username, private_key: pk };
        const pp = f.passphrase.value;
        if (pp) secret.passphrase = pp;
      } else {
        const pw = f.password.value;
        if (!pw) {
          errEl.innerHTML = '<p class="error">Password is required.</p>';
          return;
        }
        secret = { username, password: pw };
      }

      // Fetch engine encryption pubkey.
      errEl.innerHTML = '<p class="muted">Fetching engine public key&hellip;</p>';
      let pubkey;
      try {
        const pkResp = await authedFetch(`/api/v1/manage/engines/${engineID}/encryption-pubkey`);
        if (pkResp.status === 404) {
          errEl.innerHTML = '<p class="error">Engine hasn\'t registered its encryption key yet — make sure it\'s online, then retry.</p>';
          return;
        }
        if (!pkResp.ok) {
          errEl.innerHTML = `<p class="error">Failed to fetch engine pubkey: HTTP ${pkResp.status}</p>`;
          return;
        }
        const body = await pkResp.json();
        pubkey = body.pubkey;
        if (!pubkey) {
          errEl.innerHTML = '<p class="error">Engine pubkey response missing pubkey field.</p>';
          return;
        }
      } catch (e) {
        if (e.message === 'unauthorized') return;
        errEl.innerHTML = `<p class="error">Pubkey fetch failed: ${escapeHTML(e.message)}</p>`;
        return;
      }

      // Encrypt in-browser.
      errEl.innerHTML = '<p class="muted">Encrypting&hellip;</p>';
      let encrypted;
      try {
        const cryptoMod = await import('./crypto.js');
        const plaintext = new TextEncoder().encode(JSON.stringify(secret));
        encrypted = await cryptoMod.sealTo(pubkey, plaintext);
      } catch (e) {
        errEl.innerHTML = `<p class="error">Encryption failed: ${escapeHTML(e.message)}</p>`;
        return;
      }

      // POST profile.
      errEl.innerHTML = '<p class="muted">Saving&hellip;</p>';
      try {
        const resp = await authedFetch('/api/v1/manage/credentials/', {
          method: 'POST',
          body: JSON.stringify({
            name,
            auth_type: authType,
            engine_id: engineID,
            matcher,
            encrypted_secret: encrypted,
          }),
        });
        if (resp.status === 409) {
          errEl.innerHTML = '<p class="error">Engine encryption key not registered yet. Wait for the engine to check in and retry.</p>';
          return;
        }
        if (!resp.ok) {
          const txt = await resp.text();
          errEl.innerHTML = `<p class="error">Save failed: ${escapeHTML(txt || ('HTTP ' + resp.status))}</p>`;
          return;
        }
        const profile = await resp.json();
        window.location.hash = '#/credentials/' + profile.id;
      } catch (e) {
        if (e.message === 'unauthorized') return;
        errEl.innerHTML = `<p class="error">Save failed: ${escapeHTML(e.message)}</p>`;
      }
    });
  }

  async function renderCredentialDetail(el, profileID) {
    el.innerHTML = '<p>loading&hellip;</p>';
    try {
      const resp = await authedFetch('/api/v1/manage/credentials/' + profileID);
      if (!resp.ok) { el.innerHTML = '<p>Not found.</p>'; return; }
      const p = await resp.json();
      const matcher = p.matcher || {};
      const tagsRows = matcher.tags
        ? Object.entries(matcher.tags).map(([k, v]) => `<li>${escapeHTML(k)}=${escapeHTML(v)}</li>`).join('')
        : '';
      el.innerHTML = `
        <p><a href="#/credentials">&larr; Back to credentials</a></p>
        <h1>${escapeHTML(p.name)}</h1>
        <dl class="kv">
          <dt>Auth type</dt><dd><span class="badge">${escapeHTML(p.auth_type)}</span></dd>
          <dt>Engine</dt><dd>${escapeHTML(p.engine_id)}</dd>
          <dt>Secret reference</dt><dd><code>${escapeHTML(p.secret_ref || '')}</code></dd>
          <dt>Created</dt><dd>${p.created_at ? timeAgo(p.created_at) : '—'}</dd>
          <dt>Last tested</dt><dd>${p.last_tested_at ? timeAgo(p.last_tested_at) : '<em>never</em>'}</dd>
        </dl>

        <h2>Matcher</h2>
        <dl class="kv">
          <dt>Groups</dt><dd>${matcher.group_ids && matcher.group_ids.length ? matcher.group_ids.map(escapeHTML).join(', ') : '<em>(any)</em>'}</dd>
          <dt>OS</dt><dd>${matcher.os ? escapeHTML(matcher.os) : '<em>(any)</em>'}</dd>
          <dt>CIDR</dt><dd>${matcher.cidr ? escapeHTML(matcher.cidr) : '<em>(any)</em>'}</dd>
          <dt>Tags</dt><dd>${tagsRows ? `<ul>${tagsRows}</ul>` : '<em>(any)</em>'}</dd>
        </dl>

        <h2>Test</h2>
        <p class="muted">Dispatch a test job to the engine. It'll try authenticating against up to N matching hosts and return per-host results.</p>
        <form id="testForm">
          <label>Max hosts <input type="number" name="max_hosts" value="3" min="1" max="50"></label>
          <button class="primary">Run test</button>
        </form>
        <div id="test_result"></div>

        ${canMutate() ? '<h2>Danger zone</h2><button id="deleteBtn" class="danger">Delete profile</button>' : ''}
        <div id="delete_result"></div>
      `;

      el.querySelector('#testForm').addEventListener('submit', async (ev) => {
        ev.preventDefault();
        const maxHosts = parseInt(ev.target.max_hosts.value, 10) || 3;
        const rEl = el.querySelector('#test_result');
        rEl.innerHTML = '<p class="muted">Starting test&hellip;</p>';
        try {
          const r = await authedFetch(`/api/v1/manage/credentials/${profileID}/test`, {
            method: 'POST',
            body: JSON.stringify({ max_hosts: maxHosts }),
          });
          if (!r.ok) {
            const txt = await r.text();
            rEl.innerHTML = `<p class="error">${escapeHTML(txt || ('HTTP ' + r.status))}</p>`;
            return;
          }
          const data = await r.json();
          const testID = (data.job && data.job.id) || data.id;
          if (testID) {
            window.location.hash = '#/credentials/tests/' + testID;
          } else {
            rEl.innerHTML = '<p>Test started, but response had no id.</p>';
          }
        } catch (e) {
          if (e.message === 'unauthorized') return;
          rEl.innerHTML = `<p class="error">${escapeHTML(e.message)}</p>`;
        }
      });

      const delBtn = el.querySelector('#deleteBtn');
      if (delBtn) {
        delBtn.addEventListener('click', async () => {
          if (!confirm('Delete this credential profile? Associated secrets on engines will be purged.')) return;
          const rEl = el.querySelector('#delete_result');
          rEl.innerHTML = '<p class="muted">Deleting&hellip;</p>';
          try {
            const r = await authedFetch('/api/v1/manage/credentials/' + profileID, { method: 'DELETE' });
            if (!r.ok && r.status !== 204) {
              rEl.innerHTML = `<p class="error">Delete failed: HTTP ${r.status}</p>`;
              return;
            }
            window.location.hash = '#/credentials';
          } catch (e) {
            if (e.message === 'unauthorized') return;
            rEl.innerHTML = `<p class="error">${escapeHTML(e.message)}</p>`;
          }
        });
      }
    } catch (e) {
      if (e.message !== 'unauthorized') el.innerHTML = `<p>Error: ${escapeHTML(e.message)}</p>`;
    }
  }

  async function renderCredentialTestDetail(el, testID) {
    el.innerHTML = '<p>loading&hellip;</p>';
    try {
      const resp = await authedFetch('/api/v1/manage/credentials/tests/' + testID);
      if (!resp.ok) { el.innerHTML = '<p>Test not found.</p>'; return; }
      const data = await resp.json();
      const job = data.job || {};
      const results = data.results || [];
      const running = job.status === 'queued' || job.status === 'claimed' || job.status === 'running';

      el.innerHTML = `
        <p><a href="#/credentials">&larr; Back to credentials</a></p>
        <h1>Credential test</h1>
        <dl class="kv">
          <dt>Status</dt><dd><span class="badge badge-${escapeHTML(job.status || '')}">${escapeHTML(job.status || '')}</span></dd>
          <dt>Profile</dt><dd>${job.credential_profile_id ? `<a href="#/credentials/${escapeHTML(job.credential_profile_id)}">${escapeHTML(job.credential_profile_id)}</a>` : '—'}</dd>
          <dt>Max hosts</dt><dd>${job.max_hosts ?? '—'}</dd>
          <dt>Requested</dt><dd>${job.requested_at ? timeAgo(job.requested_at) : '—'}</dd>
          ${job.completed_at ? `<dt>Completed</dt><dd>${timeAgo(job.completed_at)}</dd>` : ''}
          ${job.error ? `<dt>Error</dt><dd class="error">${escapeHTML(job.error)}</dd>` : ''}
        </dl>

        <h2>Results (${results.length})</h2>
        ${results.length === 0
          ? (running ? '<p class="muted">Test in progress &mdash; results will appear here.</p>' : '<p><em>No results.</em></p>')
          : `<table>
              <thead><tr><th>Host</th><th>Status</th><th>Latency (ms)</th><th>Error</th></tr></thead>
              <tbody>${results.map(r => `<tr>
                <td>${escapeHTML(r.host_id || '')}</td>
                <td class="${r.success ? 'success-cell' : 'fail-cell'}">${r.success ? '&#10003; ok' : '&#10007; fail'}</td>
                <td>${r.latency_ms ?? '—'}</td>
                <td>${r.error ? escapeHTML(r.error) : ''}</td>
              </tr>`).join('')}</tbody>
            </table>`
        }
      `;

      if (running) {
        setTimeout(() => {
          if (window.location.hash === '#/credentials/tests/' + testID) route();
        }, 5000);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') el.innerHTML = `<p>Error: ${escapeHTML(e.message)}</p>`;
    }
  }

  // ---------- Scan Jobs (Task 11 / Phase 5) ----------

  async function renderScanJobs(el) {
    el.innerHTML = `
      <h1>Scan Jobs</h1>
      <p class="muted">Launch a scan from the Groups page via "Scan now", or directly below.</p>
      ${canMutate() ? '<p><a href="#/scan-jobs/new" class="button primary">New scan job</a></p>' : ''}
      <div id="list">loading&hellip;</div>
    `;
    try {
      const resp = await authedFetch('/api/v1/manage/scan-jobs/?limit=50');
      const jobs = await resp.json();
      const list = el.querySelector('#list');
      if (!jobs || jobs.length === 0) {
        list.innerHTML = '<p><em>No scan jobs yet.</em></p>';
        return;
      }
      list.innerHTML = `
        <table>
          <thead><tr>
            <th>Requested</th>
            <th>Profile</th>
            <th>Hosts</th>
            <th>Progress</th>
            <th>Status</th>
            <th></th>
          </tr></thead>
          <tbody>${jobs.map(j => `<tr>
            <td>${timeAgo(j.requested_at)}</td>
            <td>${escapeHTML(j.scan_profile)}</td>
            <td>${j.progress_total}</td>
            <td>${j.progress_done}/${j.progress_total}${j.progress_failed > 0 ? ` (${j.progress_failed} failed)` : ''}</td>
            <td><span class="badge badge-${j.status}">${escapeHTML(j.status)}</span></td>
            <td><a href="#/scan-jobs/${j.id}">View &rarr;</a></td>
          </tr>`).join('')}</tbody>
        </table>
      `;
    } catch (e) {
      if (e.message !== 'unauthorized') el.querySelector('#list').textContent = 'Error loading scan jobs.';
    }
  }

  async function renderNewScanJob(el) {
    if (!canMutate()) {
      el.innerHTML = '<h1>New scan job</h1><p>Only Engineers and Owners can start scans.</p>';
      return;
    }
    // Support #/scan-jobs/new?group_id=<uuid> for "Scan now" deep-link from groups page.
    const qs = window.location.hash.split('?')[1] || '';
    const params = new URLSearchParams(qs);
    const preselectedGroup = params.get('group_id') || '';

    el.innerHTML = `
      <p><a href="#/scan-jobs">&larr; Back to scan jobs</a></p>
      <h1>New scan job</h1>
      <form id="scanForm">
        <label>Target group
          <select name="group_id" id="group_sel" required>
            <option value="">&mdash; choose group &mdash;</option>
          </select>
        </label>
        <label>Scan profile
          <select name="scan_profile">
            <option value="standard" selected>standard</option>
            <option value="quick">quick</option>
            <option value="comprehensive">comprehensive</option>
          </select>
        </label>
        <label>Credential profile (optional)
          <select name="credential_profile_id" id="cred_sel">
            <option value="">&mdash; none &mdash;</option>
          </select>
          <span class="muted small">Required if hosts need SSH authentication.</span>
        </label>
        <div class="button-row">
          <a href="#/scan-jobs" class="button">Cancel</a>
          <button class="primary">Start scan</button>
        </div>
        <div id="new_err"></div>
      </form>
    `;

    try {
      const [groupsResp, credsResp] = await Promise.all([
        authedFetch('/api/v1/manage/groups/'),
        authedFetch('/api/v1/manage/credentials/'),
      ]);
      const groups = await groupsResp.json();
      const creds = await credsResp.json();
      const groupSel = el.querySelector('#group_sel');
      for (const g of groups || []) {
        const opt = document.createElement('option');
        opt.value = g.id;
        opt.textContent = g.name;
        if (g.id === preselectedGroup) opt.selected = true;
        groupSel.appendChild(opt);
      }
      const credSel = el.querySelector('#cred_sel');
      for (const c of creds || []) {
        const opt = document.createElement('option');
        opt.value = c.id;
        opt.textContent = `${c.name} (${c.auth_type})`;
        credSel.appendChild(opt);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('populate selectors', e);
    }

    el.querySelector('#scanForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const f = ev.target;
      const body = {
        group_id: f.group_id.value,
        scan_profile: f.scan_profile.value,
      };
      if (f.credential_profile_id.value) {
        body.credential_profile_id = f.credential_profile_id.value;
      }
      try {
        const resp = await authedFetch('/api/v1/manage/scan-jobs/', {
          method: 'POST',
          body: JSON.stringify(body),
        });
        if (!resp.ok) {
          const txt = await resp.text();
          el.querySelector('#new_err').innerHTML = `<p class="error">${escapeHTML(txt || ('HTTP ' + resp.status))}</p>`;
          return;
        }
        const job = await resp.json();
        window.location.hash = '#/scan-jobs/' + job.id;
      } catch (e) {
        el.querySelector('#new_err').innerHTML = `<p class="error">${escapeHTML(e.message)}</p>`;
      }
    });
  }

  async function renderScanJobDetail(el, jobID) {
    el.innerHTML = '<p>loading&hellip;</p>';
    try {
      const resp = await authedFetch('/api/v1/manage/scan-jobs/' + jobID);
      if (!resp.ok) { el.innerHTML = '<p>Not found.</p>'; return; }
      const job = await resp.json();

      const running = job.status === 'queued' || job.status === 'claimed' || job.status === 'running';
      const canCancel = canMutate() && job.status === 'queued';
      const pct = job.progress_total > 0 ? Math.round(100 * job.progress_done / job.progress_total) : 0;

      el.innerHTML = `
        <p><a href="#/scan-jobs">&larr; Back to scan jobs</a></p>
        <h1>Scan job</h1>
        <dl class="kv">
          <dt>Status</dt><dd><span class="badge badge-${job.status}">${escapeHTML(job.status)}</span></dd>
          <dt>Profile</dt><dd>${escapeHTML(job.scan_profile)}</dd>
          <dt>Hosts</dt><dd>${job.progress_total}</dd>
          <dt>Progress</dt><dd>
            ${job.progress_done} / ${job.progress_total}${job.progress_failed > 0 ? ` (${job.progress_failed} failed)` : ''}
            <span class="progress-bar"><span class="progress-bar-fill" style="width:${pct}%"></span></span>
            ${pct}%
          </dd>
          <dt>Requested</dt><dd>${timeAgo(job.requested_at)}</dd>
          ${job.claimed_at ? `<dt>Claimed</dt><dd>${timeAgo(job.claimed_at)}</dd>` : ''}
          ${job.completed_at ? `<dt>Completed</dt><dd>${timeAgo(job.completed_at)}</dd>` : ''}
          ${job.error ? `<dt>Error</dt><dd class="error">${escapeHTML(job.error)}</dd>` : ''}
        </dl>
        ${canCancel ? '<button id="cancelBtn" class="danger">Cancel job</button>' : ''}
        ${job.status === 'completed' ? '<p><a href="/ui/" class="button">View scan results &rarr;</a></p>' : ''}
      `;

      if (canCancel) {
        el.querySelector('#cancelBtn').addEventListener('click', async () => {
          if (!confirm('Cancel this scan job?')) return;
          const r = await authedFetch('/api/v1/manage/scan-jobs/' + jobID + '/cancel', { method: 'POST' });
          if (r.ok) route();
          else if (r.status === 409) alert('Job already running — cannot cancel.');
          else alert('Cancel failed: HTTP ' + r.status);
        });
      }

      if (running) {
        setTimeout(() => {
          if (window.location.hash === '#/scan-jobs/' + jobID) route();
        }, 5000);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') el.innerHTML = `<p>Error: ${escapeHTML(e.message)}</p>`;
    }
  }
  // ---------- Fleet Management (Phase 6 Task 10) ----------

  function agentStatusClass(status) {
    switch (status) {
      case 'healthy': return 'online';
      case 'unhealthy': return 'offline';
      case 'installing': return 'claimed';
      case 'uninstalled': return 'cancelled';
      default: return status;
    }
  }

  async function renderFleet(el) {
    el.innerHTML = `
      <h1>Agent Fleet</h1>
      <p class="muted">Agents are installed on hosts via SSH push. Once installed, they run scans locally and submit findings through the engine.</p>
      ${canMutate() ? '<p><a href="#/fleet/push" class="button primary">Push agent to group</a></p>' : ''}
      <h2>Installed agents</h2>
      <div id="agents">loading&hellip;</div>
      <h2>Push job history</h2>
      <div id="jobs">loading&hellip;</div>
    `;

    try {
      const [agentsResp, jobsResp] = await Promise.all([
        authedFetch('/api/v1/manage/agent-push/agents'),
        authedFetch('/api/v1/manage/agent-push/?limit=20'),
      ]);
      const agents = await agentsResp.json();
      const jobs = await jobsResp.json();

      // Agents table
      const agentsEl = el.querySelector('#agents');
      if (!agents || agents.length === 0) {
        agentsEl.innerHTML = '<p><em>No agents installed yet.</em></p>';
      } else {
        agentsEl.innerHTML = `<table>
          <thead><tr><th>Host</th><th>Status</th><th>Version</th><th>Last heartbeat</th><th>Installed</th><th></th></tr></thead>
          <tbody>${agents.map(a => `<tr>
            <td>${escapeHTML(a.host_id)}</td>
            <td><span class="badge badge-${agentStatusClass(a.status)}">${escapeHTML(a.status)}</span></td>
            <td>${escapeHTML(a.version || '\u2014')}</td>
            <td>${a.last_heartbeat ? timeAgo(a.last_heartbeat) : '\u2014'}</td>
            <td>${timeAgo(a.installed_at)}</td>
            <td>${canMutate() && a.status !== 'uninstalled' ? `<button class="uninstall danger" data-host="${escapeHTML(a.host_id)}">Uninstall</button>` : ''}</td>
          </tr>`).join('')}</tbody>
        </table>`;

        agentsEl.querySelectorAll('button.uninstall').forEach(btn => {
          btn.addEventListener('click', async () => {
            if (!confirm('Uninstall agent from this host?')) return;
            const hostID = btn.dataset.host;
            const r = await authedFetch('/api/v1/manage/agent-push/agents/' + hostID + '/uninstall', { method: 'POST' });
            if (r.ok) route();
            else alert('Uninstall failed: ' + r.status);
          });
        });
      }

      // Push jobs table
      const jobsEl = el.querySelector('#jobs');
      if (!jobs || jobs.length === 0) {
        jobsEl.innerHTML = '<p><em>No push jobs yet.</em></p>';
      } else {
        jobsEl.innerHTML = `<table>
          <thead><tr><th>Requested</th><th>Hosts</th><th>Progress</th><th>Status</th><th></th></tr></thead>
          <tbody>${jobs.map(j => `<tr>
            <td>${timeAgo(j.requested_at)}</td>
            <td>${j.progress_total}</td>
            <td>${j.progress_done}/${j.progress_total}${j.progress_failed > 0 ? ` (${j.progress_failed} failed)` : ''}</td>
            <td><span class="badge badge-${escapeHTML(j.status)}">${escapeHTML(j.status)}</span></td>
            <td><a href="#/fleet/push/${escapeHTML(j.id)}">View &rarr;</a></td>
          </tr>`).join('')}</tbody>
        </table>`;
      }
    } catch (e) {
      if (e.message !== 'unauthorized') {
        el.querySelector('#agents').textContent = 'Error loading fleet data.';
      }
    }
  }

  async function renderPushAgent(el) {
    if (!canMutate()) {
      el.innerHTML = '<h1>Push Agent</h1><p>Only Engineers and Owners can push agents.</p>';
      return;
    }

    // Parse query string from hash for group preselection
    const qs = window.location.hash.split('?')[1] || '';
    const params = new URLSearchParams(qs);
    const preselectedGroup = params.get('group_id') || '';

    el.innerHTML = `
      <h1>Push Agent to Group</h1>
      <form id="pushForm">
        <label>Target group
          <select name="group_id" required><option value="">\u2014 choose group \u2014</option></select>
        </label>
        <label>Bootstrap credential (SSH password, SSH key, or bootstrap-admin)
          <select name="credential_profile_id" required><option value="">\u2014 choose credential \u2014</option></select>
        </label>
        <div class="button-row">
          <a href="#/fleet" class="button">Cancel</a>
          <button class="primary">Push agent</button>
        </div>
        <div id="push_err"></div>
      </form>
    `;

    // Populate selectors
    try {
      const [groupsResp, credsResp] = await Promise.all([
        authedFetch('/api/v1/manage/groups/'),
        authedFetch('/api/v1/manage/credentials/'),
      ]);
      const groups = await groupsResp.json();
      const creds = await credsResp.json();
      const groupSel = el.querySelector('[name=group_id]');
      for (const g of groups || []) {
        const opt = document.createElement('option');
        opt.value = g.id;
        opt.textContent = g.name;
        if (g.id === preselectedGroup) opt.selected = true;
        groupSel.appendChild(opt);
      }
      const credSel = el.querySelector('[name=credential_profile_id]');
      for (const c of creds || []) {
        if (c.auth_type === 'ssh-password' || c.auth_type === 'bootstrap-admin' || c.auth_type === 'ssh-key') {
          const opt = document.createElement('option');
          opt.value = c.id;
          opt.textContent = escapeHTML(c.name) + ' (' + escapeHTML(c.auth_type) + ')';
          credSel.appendChild(opt);
        }
      }
    } catch (e) {
      // Selector population failed — form still usable if user types UUIDs, but
      // more practically this means the API is unreachable. Error ignored per
      // existing pattern (renderNewScanJob does the same).
    }

    el.querySelector('#pushForm').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const body = {
        group_id: ev.target.group_id.value,
        credential_profile_id: ev.target.credential_profile_id.value,
      };
      const resp = await authedFetch('/api/v1/manage/agent-push/', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        const txt = await resp.text();
        el.querySelector('#push_err').innerHTML = '<p class="error">' + escapeHTML(txt) + '</p>';
        return;
      }
      const job = await resp.json();
      window.location.hash = '#/fleet/push/' + job.id;
    });
  }

  async function renderPushJobDetail(el, jobID) {
    el.innerHTML = '<p>loading&hellip;</p>';
    try {
      const resp = await authedFetch('/api/v1/manage/agent-push/' + jobID);
      if (!resp.ok) { el.innerHTML = '<p>Not found.</p>'; return; }
      const job = await resp.json();

      const running = ['queued', 'claimed', 'running'].includes(job.status);
      const canCancel = canMutate() && job.status === 'queued';
      const pct = job.progress_total > 0 ? Math.round(100 * job.progress_done / job.progress_total) : 0;

      el.innerHTML = `
        <p><a href="#/fleet">&larr; Back to fleet</a></p>
        <h1>Push Job</h1>
        <dl class="kv">
          <dt>Status</dt><dd><span class="badge badge-${escapeHTML(job.status)}">${escapeHTML(job.status)}</span></dd>
          <dt>Hosts</dt><dd>${job.progress_total}</dd>
          <dt>Progress</dt><dd>
            ${job.progress_done} installed${job.progress_failed > 0 ? ', ' + job.progress_failed + ' failed' : ''} (${pct}%)
            <span class="progress-bar"><span class="progress-bar-fill" style="width:${pct}%"></span></span>
          </dd>
          <dt>Requested</dt><dd>${timeAgo(job.requested_at)}</dd>
          ${job.claimed_at ? '<dt>Claimed</dt><dd>' + timeAgo(job.claimed_at) + '</dd>' : ''}
          ${job.completed_at ? '<dt>Completed</dt><dd>' + timeAgo(job.completed_at) + '</dd>' : ''}
          ${job.error ? '<dt>Error</dt><dd class="error">' + escapeHTML(job.error) + '</dd>' : ''}
        </dl>
        ${canCancel ? '<button id="cancelPush" class="danger">Cancel</button>' : ''}
      `;

      if (canCancel) {
        el.querySelector('#cancelPush').addEventListener('click', async () => {
          if (!confirm('Cancel this push job?')) return;
          const r = await authedFetch('/api/v1/manage/agent-push/' + jobID + '/cancel', { method: 'POST' });
          if (r.ok) route();
          else alert('Cancel failed: ' + r.status);
        });
      }

      if (running) {
        setTimeout(() => {
          if (window.location.hash === '#/fleet/push/' + jobID) route();
        }, 5000);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') el.innerHTML = '<p>Error: ' + escapeHTML(e.message) + '</p>';
    }
  }

  // ---------- Audit Log (Phase 7 Task 8) ----------

  async function renderAudit(el) {
    if (!isOwner()) {
      el.innerHTML = '<h1>Audit Log</h1><p>Only admins can view the audit log.</p>';
      return;
    }
    el.innerHTML = `
      <h1>Audit Log</h1>
      <p class="muted">All actions across inventory, credentials, scans, engines, and user management.</p>
      <div class="filter-row">
        <input type="text" id="audit_search" placeholder="Filter by event type or target\u2026">
        <button id="audit_refresh" class="button">Refresh</button>
      </div>
      <div id="audit_list">loading\u2026</div>
    `;
    const load = async () => {
      const search = (el.querySelector('#audit_search')?.value || '').trim();
      let url = '/api/v1/audit?limit=200';
      if (search) url += '&event_type=' + encodeURIComponent(search);
      try {
        const resp = await authedFetch(url);
        if (!resp.ok) {
          el.querySelector('#audit_list').innerHTML = '<p class="error">Failed to load audit log.</p>';
          return;
        }
        const events = await resp.json();
        const list = el.querySelector('#audit_list');
        if (!events || events.length === 0) {
          list.innerHTML = '<p><em>No events found.</em></p>';
          return;
        }
        // Client-side substring filter when the server-side event_type
        // filter requires an exact match but the user typed a partial.
        const filtered = search
          ? events.filter(e =>
              (e.eventType || '').includes(search) ||
              (e.targetID || '').includes(search))
          : events;
        list.innerHTML = renderAuditTable(filtered);
      } catch (e) {
        if (e.message !== 'unauthorized') {
          el.querySelector('#audit_list').innerHTML = '<p class="error">Error loading audit log.</p>';
        }
      }
    };
    await load();
    el.querySelector('#audit_refresh')?.addEventListener('click', load);
    el.querySelector('#audit_search')?.addEventListener('keyup', (e) => {
      if (e.key === 'Enter') load();
    });
  }

  function renderAuditTable(events) {
    return `<table>
      <thead><tr><th>Time</th><th>Event</th><th>Target</th><th>Actor</th><th>IP</th><th>Details</th></tr></thead>
      <tbody>${events.map(e => {
        const details = e.details ? JSON.stringify(e.details) : '';
        return `<tr>
          <td>${timeAgo(e.timestamp)}</td>
          <td><code>${escapeHTML(e.eventType)}</code></td>
          <td><code class="muted">${escapeHTML(e.targetID || '')}</code></td>
          <td class="muted">${escapeHTML(e.actorID || '')}</td>
          <td class="muted">${escapeHTML(e.ipAddress || '')}</td>
          <td class="muted audit-details">${escapeHTML(details.length > 120 ? details.slice(0, 120) + '\u2026' : details)}</td>
        </tr>`;
      }).join('')}</tbody>
    </table>`;
  }

})();
