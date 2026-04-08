// Triton Dashboard SPA
(function() {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);
  const content = $('#content');

  // ─── Auth state ─────────────────────────────────────────────────────
  // JWT lives in localStorage. We treat the token as opaque — the server
  // is the only validator. We DO decode the payload (base64url, no
  // signature check) to read role/name/org/mcp claims for client-side
  // routing decisions only. NEVER trust these for authorization.
  const STORAGE_KEY = 'tritonJWT';
  const auth = {
    getToken: () => localStorage.getItem(STORAGE_KEY) || '',
    setToken: (t) => localStorage.setItem(STORAGE_KEY, t),
    clearToken: () => localStorage.removeItem(STORAGE_KEY),
    getClaims: () => {
      const token = auth.getToken();
      if (!token) return null;
      try {
        const payload = token.split('.')[1];
        // Base64url → base64 → JSON
        const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
        return JSON.parse(json);
      } catch (e) { return null; }
    },
    isAdmin: () => {
      const c = auth.getClaims();
      return c && c.role === 'org_admin';
    },
    mustChangePassword: () => {
      const c = auth.getClaims();
      return !!(c && c.mcp);
    },
  };

  // API helper. Injects Authorization header from stored JWT, handles
  // 401 by clearing the token and showing the login screen.
  // method/body are optional (defaults to GET).
  async function api(path, opts) {
    opts = opts || {};
    const headers = Object.assign({}, opts.headers || {});
    const token = auth.getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    if (opts.body && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    const resp = await fetch('/api/v1' + path, {
      method: opts.method || 'GET',
      headers,
      body: opts.body || undefined,
    });
    if (resp.status === 401) {
      auth.clearToken();
      location.hash = '#/login';
      throw new Error('Authentication required');
    }
    if (!resp.ok) {
      let msg = `API error: ${resp.status}`;
      try {
        const err = await resp.json();
        if (err.error) msg = err.error;
      } catch (_) {}
      throw new Error(msg);
    }
    if (resp.status === 204) return null;
    return resp.json();
  }

  // Dark theme chart colors matching CSS variables
  const COLORS = {
    safe: '#34d399',
    transitional: '#fbbf24',
    deprecated: '#fb923c',
    unsafe: '#f87171',
    info: '#22d3ee'
  };

  // Chart.js dark theme defaults
  const CHART_DEFAULTS = {
    color: '#94a3b8',
    borderColor: 'rgba(148, 163, 184, 0.06)',
    font: { family: "'Outfit', system-ui, sans-serif" }
  };

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // Router
  function route() {
    const hash = location.hash || '#/';
    const parts = hash.slice(2).split('/');
    const view = parts[0] || '';
    const param = parts[1] || '';

    // Auth gate: if the user has a JWT and it says they must change
    // their password, force them to the change-password screen first.
    // No other view is reachable until the flag is cleared.
    if (auth.mustChangePassword() && view !== 'change-password' && view !== 'login') {
      location.hash = '#/change-password';
      return;
    }

    // Update active nav link
    $$('.nav-link').forEach(a => {
      a.classList.toggle('active', a.dataset.view === (view || 'overview'));
    });

    // Show/hide the Users nav link based on role.
    const usersLink = $('#nav-users');
    if (usersLink) {
      usersLink.style.display = auth.isAdmin() ? '' : 'none';
    }
    // Show/hide the logout button based on whether we have a token.
    const logoutBtn = $('#nav-logout');
    if (logoutBtn) {
      logoutBtn.style.display = auth.getToken() ? '' : 'none';
    }

    switch(view) {
      case 'login': renderLogin(); break;
      case 'change-password': renderChangePassword(); break;
      case 'users': param ? renderUserDetail(param) : renderUsers(); break;
      case '':
      case 'overview': renderOverview(); break;
      case 'machines': param ? renderMachineDetail(param) : renderMachines(); break;
      case 'scans': param ? renderScanDetail(param) : renderScans(); break;
      case 'diff': renderDiff(); break;
      case 'trend': renderTrend(); break;
      default: content.innerHTML = '<div class="error">Page not found</div>';
    }
  }

  // ─── Login view (Phase 3.1) ─────────────────────────────────────────
  function renderLogin() {
    content.innerHTML = `
      <div class="auth-card">
        <h2>Sign in</h2>
        <p class="muted">Sign in to view your organization's scan reports.</p>
        <form id="loginForm" onsubmit="return tritonLogin(event)">
          <label>Email
            <input type="email" id="loginEmail" required autofocus>
          </label>
          <label>Password
            <input type="password" id="loginPassword" required>
          </label>
          <button type="submit" class="btn btn-primary">Sign in</button>
          <div id="loginError" class="form-error"></div>
        </form>
      </div>
    `;
  }

  window.tritonLogin = async function(e) {
    e.preventDefault();
    const email = $('#loginEmail').value.trim();
    const password = $('#loginPassword').value;
    const errEl = $('#loginError');
    errEl.textContent = '';
    try {
      const resp = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({email, password}),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        errEl.textContent = err.error || `Sign in failed (${resp.status})`;
        return false;
      }
      const data = await resp.json();
      auth.setToken(data.token);
      // If the response says the user must change their password, route
      // them there. Otherwise drop them onto the overview.
      if (data.mustChangePassword) {
        location.hash = '#/change-password';
      } else {
        location.hash = '#/';
      }
    } catch (e) {
      errEl.textContent = 'Network error: ' + e.message;
    }
    return false;
  };

  // ─── Change password view (Phase 3.4) ───────────────────────────────
  function renderChangePassword() {
    if (!auth.getToken()) {
      location.hash = '#/login';
      return;
    }
    const claims = auth.getClaims();
    const reasonNote = (claims && claims.mcp)
      ? '<p class="warn">Your account requires a password change before you can continue.</p>'
      : '';
    content.innerHTML = `
      <div class="auth-card">
        <h2>Change password</h2>
        ${reasonNote}
        <form id="changePwForm" onsubmit="return tritonChangePassword(event)">
          <label>Current password
            <input type="password" id="cpwCurrent" required autofocus>
          </label>
          <label>New password (min 12 characters)
            <input type="password" id="cpwNew" required minlength="12">
          </label>
          <label>Confirm new password
            <input type="password" id="cpwConfirm" required minlength="12">
          </label>
          <button type="submit" class="btn btn-primary">Change password</button>
          <div id="cpwError" class="form-error"></div>
        </form>
      </div>
    `;
  }

  window.tritonChangePassword = async function(e) {
    e.preventDefault();
    const current = $('#cpwCurrent').value;
    const newPw = $('#cpwNew').value;
    const confirm = $('#cpwConfirm').value;
    const errEl = $('#cpwError');
    errEl.textContent = '';
    if (newPw !== confirm) {
      errEl.textContent = "New passwords don't match.";
      return false;
    }
    try {
      const data = await api('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({current_password: current, new_password: newPw}),
      });
      // Server returns a fresh JWT with mcp=false. Store and continue.
      if (data && data.token) {
        auth.setToken(data.token);
      }
      location.hash = '#/';
    } catch (err) {
      errEl.textContent = err.message;
    }
    return false;
  };

  // ─── Logout ─────────────────────────────────────────────────────────
  window.tritonLogout = async function() {
    try {
      await api('/auth/logout', {method: 'POST'});
    } catch (_) {
      // Best-effort — clear local state regardless
    }
    auth.clearToken();
    location.hash = '#/login';
  };

  // ─── Users view (Phase 3.3 — org admins only) ───────────────────────
  async function renderUsers() {
    if (!auth.isAdmin()) {
      content.innerHTML = '<div class="error">Access denied — org admin role required.</div>';
      return;
    }
    content.innerHTML = '<div class="loading">Loading users...</div>';
    try {
      const users = await api('/users');
      let html = `<div class="view-header">
        <h2>Users</h2>
        <button class="btn btn-primary" onclick="tritonShowCreateUser()">Add user</button>
      </div>`;
      html += `<div id="userFormContainer"></div>`;
      html += `<table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Created</th><th></th></tr></thead>
        <tbody>`;
      if (users && users.length) {
        for (const u of users) {
          html += `<tr>
            <td>${escapeHtml(u.name)}</td>
            <td>${escapeHtml(u.email)}</td>
            <td><span class="badge">${escapeHtml(u.role)}</span></td>
            <td>${formatDate(u.createdAt)}</td>
            <td><button class="btn btn-outline btn-sm" onclick="tritonDeleteUser('${escapeHtml(u.id)}', '${escapeHtml(u.email)}')">Delete</button></td>
          </tr>`;
        }
      } else {
        html += `<tr><td colspan="5" class="muted">No users yet.</td></tr>`;
      }
      html += `</tbody></table>`;
      content.innerHTML = html;
    } catch (e) {
      content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
  }

  window.tritonShowCreateUser = function() {
    $('#userFormContainer').innerHTML = `
      <div class="auth-card">
        <h3>Add user</h3>
        <form id="createUserForm" onsubmit="return tritonCreateUser(event)">
          <label>Email <input type="email" id="newUserEmail" required></label>
          <label>Name <input type="text" id="newUserName" required></label>
          <label>Role
            <select id="newUserRole">
              <option value="org_user">org_user (read-only)</option>
              <option value="org_admin">org_admin (full access)</option>
            </select>
          </label>
          <label>Password (min 12 characters)
            <input type="password" id="newUserPassword" required minlength="12">
          </label>
          <button type="submit" class="btn btn-primary">Create</button>
          <button type="button" class="btn btn-outline" onclick="tritonCancelCreateUser()">Cancel</button>
          <div id="newUserError" class="form-error"></div>
        </form>
      </div>
    `;
  };

  window.tritonCancelCreateUser = function() {
    $('#userFormContainer').innerHTML = '';
  };

  window.tritonCreateUser = async function(e) {
    e.preventDefault();
    const errEl = $('#newUserError');
    errEl.textContent = '';
    try {
      await api('/users', {
        method: 'POST',
        body: JSON.stringify({
          email: $('#newUserEmail').value.trim(),
          name: $('#newUserName').value.trim(),
          role: $('#newUserRole').value,
          password: $('#newUserPassword').value,
        }),
      });
      renderUsers();
    } catch (err) {
      errEl.textContent = err.message;
    }
    return false;
  };

  window.tritonDeleteUser = async function(id, email) {
    if (!confirm('Delete user ' + email + '? This cannot be undone.')) return;
    try {
      await api('/users/' + encodeURIComponent(id), {method: 'DELETE'});
      renderUsers();
    } catch (err) {
      alert('Delete failed: ' + err.message);
    }
  };

  // renderUserDetail is a stub for #/users/{id} — currently routes back
  // to the list. Reserved for a future per-user edit screen.
  function renderUserDetail(_id) {
    location.hash = '#/users';
  }

  // Render helpers
  function badge(status) {
    const s = escapeHtml((status || '').toUpperCase());
    return `<span class="badge badge-${escapeHtml((status || '').toLowerCase())}">${s}</span>`;
  }

  function formatDate(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
  }

  // Chart.js dark theme options
  function darkChartOptions(extra) {
    return Object.assign({
      responsive: true,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: CHART_DEFAULTS.color,
            font: CHART_DEFAULTS.font,
            padding: 16
          }
        }
      }
    }, extra || {});
  }

  function darkScaleOptions(stacked) {
    return {
      x: {
        stacked: !!stacked,
        ticks: { color: CHART_DEFAULTS.color, font: CHART_DEFAULTS.font },
        grid: { color: CHART_DEFAULTS.borderColor }
      },
      y: {
        stacked: !!stacked,
        ticks: { color: CHART_DEFAULTS.color, font: CHART_DEFAULTS.font },
        grid: { color: CHART_DEFAULTS.borderColor }
      }
    };
  }

  // Overview
  async function renderOverview() {
    content.innerHTML = '<div class="loading">Loading overview...</div>';
    try {
      const agg = await api('/aggregate');
      let html = `<h2>Organization Overview</h2>`;

      html += `<div class="card-grid">
        <div class="card info"><div class="value">${escapeHtml(agg.machineCount)}</div><div class="label">Machines</div></div>
        <div class="card info"><div class="value">${escapeHtml(agg.totalFindings)}</div><div class="label">Total Findings</div></div>
        <div class="card safe"><div class="value">${escapeHtml(agg.safe)}</div><div class="label">Safe</div></div>
        <div class="card transitional"><div class="value">${escapeHtml(agg.transitional)}</div><div class="label">Transitional</div></div>
        <div class="card deprecated"><div class="value">${escapeHtml(agg.deprecated)}</div><div class="label">Deprecated</div></div>
        <div class="card unsafe"><div class="value">${escapeHtml(agg.unsafe)}</div><div class="label">Unsafe</div></div>
      </div>`;

      html += `<div class="charts-row">
        <div class="chart-box"><h3>PQC Status Distribution</h3><canvas id="donutChart" width="300" height="300"></canvas></div>
        <div class="chart-box"><h3>Machines by Risk</h3><canvas id="barChart" width="400" height="300"></canvas></div>
      </div>`;

      // Machines table
      if (agg.machines && agg.machines.length > 0) {
        html += `<h3>Machines</h3><table>
          <thead><tr><th>Hostname</th><th>Last Scan</th><th>Findings</th><th>Safe</th><th>Trans.</th><th>Depr.</th><th>Unsafe</th></tr></thead>
          <tbody>`;
        for (const m of agg.machines) {
          html += `<tr onclick="location.hash='#/machines/${escapeHtml(m.hostname)}'">
            <td>${escapeHtml(m.hostname)}</td><td>${formatDate(m.timestamp)}</td>
            <td>${escapeHtml(m.totalFindings)}</td>
            <td>${escapeHtml(m.safe)}</td><td>${escapeHtml(m.transitional)}</td>
            <td>${escapeHtml(m.deprecated)}</td><td>${escapeHtml(m.unsafe)}</td></tr>`;
        }
        html += `</tbody></table>`;
      }

      content.innerHTML = html;

      // Charts
      renderDonutChart(agg);
      renderBarChart(agg);
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderDonutChart(agg) {
    const ctx = document.getElementById('donutChart');
    if (!ctx) return;
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Safe', 'Transitional', 'Deprecated', 'Unsafe'],
        datasets: [{
          data: [agg.safe, agg.transitional, agg.deprecated, agg.unsafe],
          backgroundColor: [COLORS.safe, COLORS.transitional, COLORS.deprecated, COLORS.unsafe],
          borderColor: '#0a1628',
          borderWidth: 2
        }]
      },
      options: darkChartOptions()
    });
  }

  function renderBarChart(agg) {
    const ctx = document.getElementById('barChart');
    if (!ctx || !agg.machines) return;
    const sorted = [...agg.machines].sort((a,b) => (b.unsafe*4+b.deprecated*3) - (a.unsafe*4+a.deprecated*3));
    const top = sorted.slice(0, 10);

    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: top.map(m => m.hostname),
        datasets: [
          { label: 'Unsafe', data: top.map(m => m.unsafe), backgroundColor: COLORS.unsafe },
          { label: 'Deprecated', data: top.map(m => m.deprecated), backgroundColor: COLORS.deprecated },
          { label: 'Transitional', data: top.map(m => m.transitional), backgroundColor: COLORS.transitional },
          { label: 'Safe', data: top.map(m => m.safe), backgroundColor: COLORS.safe }
        ]
      },
      options: darkChartOptions({ scales: darkScaleOptions(true) })
    });
  }

  // Machines list
  async function renderMachines() {
    content.innerHTML = '<div class="loading">Loading machines...</div>';
    try {
      const machines = await api('/machines');
      let html = `<h2>Machines</h2><table>
        <thead><tr><th>Hostname</th><th>Latest Scan ID</th><th>Scan Time</th><th>Findings</th></tr></thead>
        <tbody>`;
      for (const m of machines) {
        html += `<tr onclick="location.hash='#/machines/${escapeHtml(m.hostname)}'">
          <td>${escapeHtml(m.hostname)}</td><td>${escapeHtml(m.id)}</td>
          <td>${formatDate(m.timestamp)}</td><td>${escapeHtml(m.totalFindings)}</td></tr>`;
      }
      html += `</tbody></table>`;
      content.innerHTML = html;
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
  }

  // Machine detail
  async function renderMachineDetail(hostname) {
    content.innerHTML = '<div class="loading">Loading machine...</div>';
    try {
      const scans = await api(`/machines/${hostname}`);
      let html = `<div class="view-header"><h2>Machine: ${escapeHtml(hostname)}</h2>
        <button class="btn btn-outline" onclick="location.hash='#/machines'">Back</button></div>`;

      html += `<table>
        <thead><tr><th>Scan ID</th><th>Time</th><th>Profile</th><th>Findings</th><th>Safe</th><th>Trans.</th><th>Depr.</th><th>Unsafe</th></tr></thead>
        <tbody>`;
      for (const s of scans) {
        html += `<tr onclick="location.hash='#/scans/${escapeHtml(s.id)}'">
          <td>${escapeHtml(s.id.slice(0,8))}...</td>
          <td>${formatDate(s.timestamp)}</td><td>${escapeHtml(s.profile)}</td>
          <td>${escapeHtml(s.totalFindings)}</td>
          <td>${escapeHtml(s.safe)}</td><td>${escapeHtml(s.transitional)}</td>
          <td>${escapeHtml(s.deprecated)}</td><td>${escapeHtml(s.unsafe)}</td></tr>`;
      }
      html += `</tbody></table>`;

      // Trend chart
      if (scans.length >= 2) {
        html += `<div class="chart-box"><h3>Trend</h3><canvas id="trendChart" width="600" height="300"></canvas></div>`;
      }

      content.innerHTML = html;

      if (scans.length >= 2) {
        renderMachineTrend(scans);
      }
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderMachineTrend(scans) {
    const ctx = document.getElementById('trendChart');
    if (!ctx) return;
    const reversed = [...scans].reverse();
    new Chart(ctx, {
      type: 'line',
      data: {
        labels: reversed.map(s => new Date(s.timestamp).toLocaleDateString()),
        datasets: [
          { label: 'Safe', data: reversed.map(s => s.safe), borderColor: COLORS.safe, backgroundColor: 'rgba(52,211,153,0.08)', fill: true, tension: 0.3 },
          { label: 'Transitional', data: reversed.map(s => s.transitional), borderColor: COLORS.transitional, fill: false, tension: 0.3 },
          { label: 'Deprecated', data: reversed.map(s => s.deprecated), borderColor: COLORS.deprecated, fill: false, tension: 0.3 },
          { label: 'Unsafe', data: reversed.map(s => s.unsafe), borderColor: COLORS.unsafe, fill: false, tension: 0.3 }
        ]
      },
      options: darkChartOptions({ scales: darkScaleOptions(false) })
    });
  }

  // Scans list
  async function renderScans() {
    content.innerHTML = '<div class="loading">Loading scans...</div>';
    try {
      const scans = await api('/scans');
      let html = `<h2>All Scans</h2><table>
        <thead><tr><th>ID</th><th>Hostname</th><th>Time</th><th>Profile</th><th>Findings</th><th>Safe</th><th>Unsafe</th></tr></thead>
        <tbody>`;
      for (const s of scans) {
        html += `<tr onclick="location.hash='#/scans/${escapeHtml(s.id)}'">
          <td>${escapeHtml(s.id.slice(0,8))}...</td><td>${escapeHtml(s.hostname)}</td>
          <td>${formatDate(s.timestamp)}</td><td>${escapeHtml(s.profile)}</td>
          <td>${escapeHtml(s.totalFindings)}</td><td>${escapeHtml(s.safe)}</td><td>${escapeHtml(s.unsafe)}</td></tr>`;
      }
      html += `</tbody></table>`;
      content.innerHTML = html;
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
  }

  // Scan detail
  async function renderScanDetail(id) {
    content.innerHTML = '<div class="loading">Loading scan...</div>';
    try {
      const scan = await api(`/scans/${id}`);
      let html = `<div class="view-header"><h2>Scan: ${escapeHtml(id.slice(0,12))}...</h2>
        <button class="btn btn-outline" onclick="location.hash='#/scans'">Back</button></div>`;

      html += `<div class="card-grid">
        <div class="card info"><div class="value">${escapeHtml(scan.metadata.hostname)}</div><div class="label">Hostname</div></div>
        <div class="card info"><div class="value">${escapeHtml(scan.metadata.scanProfile)}</div><div class="label">Profile</div></div>
        <div class="card info"><div class="value">${escapeHtml(scan.summary.totalFindings)}</div><div class="label">Total Findings</div></div>
        <div class="card safe"><div class="value">${escapeHtml(scan.summary.safe)}</div><div class="label">Safe</div></div>
        <div class="card transitional"><div class="value">${escapeHtml(scan.summary.transitional)}</div><div class="label">Transitional</div></div>
        <div class="card deprecated"><div class="value">${escapeHtml(scan.summary.deprecated)}</div><div class="label">Deprecated</div></div>
        <div class="card unsafe"><div class="value">${escapeHtml(scan.summary.unsafe)}</div><div class="label">Unsafe</div></div>
      </div>`;

      // Findings table
      if (scan.findings && scan.findings.length > 0) {
        html += `<h3>Findings</h3><table>
          <thead><tr><th>Module</th><th>Source</th><th>Algorithm</th><th>PQC Status</th><th>Key Size</th></tr></thead>
          <tbody>`;
        for (const f of scan.findings) {
          const algo = f.cryptoAsset ? f.cryptoAsset.algorithm : '-';
          const status = f.cryptoAsset ? f.cryptoAsset.pqcStatus : '-';
          const keySize = f.cryptoAsset && f.cryptoAsset.keySize ? f.cryptoAsset.keySize : '-';
          const source = f.source.path || f.source.endpoint || '-';
          html += `<tr>
            <td>${escapeHtml(f.module)}</td><td>${escapeHtml(source)}</td>
            <td>${escapeHtml(algo)}</td><td>${badge(status)}</td><td>${escapeHtml(keySize)}</td></tr>`;
        }
        html += `</tbody></table>`;
      }

      // Systems table
      if (scan.systems && scan.systems.length > 0) {
        html += `<h3>Systems</h3><table>
          <thead><tr><th>Name</th><th>Criticality</th><th>Crypto Assets</th></tr></thead>
          <tbody>`;
        for (const sys of scan.systems) {
          html += `<tr><td>${escapeHtml(sys.name)}</td><td>${escapeHtml(sys.criticalityLevel || '-')}</td>
            <td>${(sys.cryptoAssets || []).length}</td></tr>`;
        }
        html += `</tbody></table>`;
      }

      content.innerHTML = html;
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
  }

  // Diff view
  async function renderDiff() {
    content.innerHTML = `<h2>Scan Comparison</h2>
      <div class="form-row">
        <label>Base Scan ID <input id="diffBase" type="text" placeholder="scan-id-1"></label>
        <label>Compare Scan ID <input id="diffCompare" type="text" placeholder="scan-id-2"></label>
        <button class="btn" onclick="runDiff()">Compare</button>
      </div>
      <div id="diffResult"></div>`;
  }

  window.runDiff = async function() {
    const base = $('#diffBase').value.trim();
    const compare = $('#diffCompare').value.trim();
    const el = $('#diffResult');
    if (!base || !compare) { el.innerHTML = '<div class="error">Enter both scan IDs</div>'; return; }

    el.innerHTML = '<div class="loading">Computing diff...</div>';
    try {
      const diff = await api(`/diff?base=${base}&compare=${compare}`);
      let html = `<div class="card-grid">
        <div class="card safe"><div class="value">${escapeHtml(diff.addedCount || 0)}</div><div class="label">Added</div></div>
        <div class="card unsafe"><div class="value">${escapeHtml(diff.removedCount || 0)}</div><div class="label">Removed</div></div>
        <div class="card transitional"><div class="value">${escapeHtml(diff.changedCount || 0)}</div><div class="label">Changed</div></div>
      </div>`;

      if (diff.added && diff.added.length > 0) {
        html += `<h3>Added Findings</h3><table class="diff-added">
          <thead><tr><th>Module</th><th>Algorithm</th><th>Status</th></tr></thead>
          <tbody>`;
        for (const f of diff.added) {
          html += `<tr><td>${escapeHtml(f.module)}</td><td>${escapeHtml(f.cryptoAsset ? f.cryptoAsset.algorithm : '-')}</td>
            <td>${badge(f.cryptoAsset ? f.cryptoAsset.pqcStatus : '')}</td></tr>`;
        }
        html += `</tbody></table>`;
      }

      if (diff.removed && diff.removed.length > 0) {
        html += `<h3>Removed Findings</h3><table class="diff-removed">
          <thead><tr><th>Module</th><th>Algorithm</th><th>Status</th></tr></thead>
          <tbody>`;
        for (const f of diff.removed) {
          html += `<tr><td>${escapeHtml(f.module)}</td><td>${escapeHtml(f.cryptoAsset ? f.cryptoAsset.algorithm : '-')}</td>
            <td>${badge(f.cryptoAsset ? f.cryptoAsset.pqcStatus : '')}</td></tr>`;
        }
        html += `</tbody></table>`;
      }

      el.innerHTML = html;
    } catch(e) {
      el.innerHTML = `<div class="error">Diff failed: ${escapeHtml(e.message)}</div>`;
    }
  };

  // Trend view
  async function renderTrend() {
    content.innerHTML = `<h2>Migration Trend</h2>
      <div class="form-row">
        <label>Hostname <input id="trendHost" type="text" placeholder="hostname"></label>
        <label>Last N <input id="trendLast" type="number" value="10" min="2" max="50"></label>
        <button class="btn" onclick="runTrend()">Show Trend</button>
      </div>
      <div id="trendResult"></div>`;
  }

  window.runTrend = async function() {
    const host = $('#trendHost').value.trim();
    const last = $('#trendLast').value || 10;
    const el = $('#trendResult');

    let url = `/trend?last=${last}`;
    if (host) url += `&hostname=${host}`;

    el.innerHTML = '<div class="loading">Computing trend...</div>';
    try {
      const trend = await api(url);

      let html = '';
      if (trend.direction) {
        const dir = escapeHtml(trend.direction);
        const cls = trend.direction === 'improving' ? 'improving' : trend.direction === 'declining' ? 'declining' : 'stable';
        html += `<div class="direction-badge ${cls}">${dir}</div>`;
      }

      if (trend.points && trend.points.length > 0) {
        html += `<div class="chart-box"><canvas id="trendLineChart" width="600" height="300"></canvas></div>`;
      }

      el.innerHTML = html;

      if (trend.points && trend.points.length > 0) {
        const ctx = document.getElementById('trendLineChart');
        new Chart(ctx, {
          type: 'line',
          data: {
            labels: trend.points.map(p => new Date(p.timestamp).toLocaleDateString()),
            datasets: [
              { label: 'Safe', data: trend.points.map(p => p.safe), borderColor: COLORS.safe, backgroundColor: 'rgba(52,211,153,0.08)', fill: true, tension: 0.3 },
              { label: 'Transitional', data: trend.points.map(p => p.transitional), borderColor: COLORS.transitional, fill: false, tension: 0.3 },
              { label: 'Deprecated', data: trend.points.map(p => p.deprecated), borderColor: COLORS.deprecated, fill: false, tension: 0.3 },
              { label: 'Unsafe', data: trend.points.map(p => p.unsafe), borderColor: COLORS.unsafe, fill: false, tension: 0.3 }
            ]
          },
          options: darkChartOptions({ scales: darkScaleOptions(false) })
        });
      }
    } catch(e) {
      el.innerHTML = `<div class="error">Trend failed: ${escapeHtml(e.message)}</div>`;
    }
  };

  // Init
  // The renderOverview() initial call will hit the API. In single-tenant
  // mode (Guard provides tenant context), it returns 200 and the UI
  // renders normally — no login needed. In multi-tenant mode without
  // a stored token, the API returns 401, the api() helper redirects
  // to #/login, and the user signs in.
  window.addEventListener('hashchange', route);
  route();
})();
