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
    // isTokenExpired returns true if the stored JWT's exp claim is in the
    // past (or unparseable). Returns false if there is no token at all
    // (caller should check getToken() separately for that case).
    isTokenExpired: () => {
      const c = auth.getClaims();
      if (!c || !c.exp) return true;
      return Date.now() / 1000 >= c.exp;
    },
  };

  // Analytics Phase 1 — backfill banner state. The api() helper syncs
  // backfillState.inProgress from the X-Backfill-In-Progress response
  // header whenever an analytics endpoint is called. The state is
  // read by renderBackfillBanner() which prepends a cyan notice to
  // any analytics view while backfill is running, and auto-clears
  // once the header stops being set.
  const backfillState = { inProgress: false };
  const ANALYTICS_PATHS = ['/inventory', '/certificates', '/priority', '/executive'];

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
    // Sync backfill state on every analytics response. Done BEFORE
    // 401 handling so a 401 bounce still updates the flag (unlikely
    // to matter in practice but cheap and consistent).
    if (ANALYTICS_PATHS.some(p => path.startsWith(p))) {
      backfillState.inProgress = resp.headers.get('X-Backfill-In-Progress') === 'true';
    }
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

  // renderBackfillBanner prepends a cyan "still populating historical
  // data" banner to the given container if the most recent analytics
  // response advertised X-Backfill-In-Progress: true. Zero effect
  // once backfill finishes — the next api() call clears the flag.
  function renderBackfillBanner(containerEl) {
    if (!backfillState.inProgress) return;
    containerEl.insertAdjacentHTML('afterbegin',
      '<div class="backfill-banner">' +
        '<svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="2">' +
          '<circle cx="7" cy="7" r="5" stroke-dasharray="20 8"/>' +
        '</svg>' +
        '<span>Triton is still populating historical scan data — this view may be incomplete. Refresh in a moment for more.</span>' +
      '</div>');
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

  // escapeHtml escapes the five XML-significant characters. Single quote
  // MUST be escaped because we use double-quoted HTML attributes, but
  // any interpolation inside an inline JS string literal (onclick="...('${x}')")
  // would otherwise be broken out of by a single quote. The safer pattern
  // is to avoid inline handlers entirely — see the delete-user button
  // below, which uses data-* attrs + addEventListener.
  function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  // wireClickableRows finds every element with class="clickable-row"
  // and data-href="#/..." and attaches a click handler that sets
  // location.hash. This replaces inline onclick="location.hash='...'"
  // patterns that interpolated user-controlled strings (hostnames,
  // scan IDs) and were XSS vectors the moment any one of them
  // contained a quote or `</script>`. data-href values are HTML
  // attribute-encoded by escapeHtml, so the browser parser sees them
  // as opaque strings, not JavaScript.
  function wireClickableRows() {
    $$('.clickable-row').forEach(el => {
      el.addEventListener('click', () => {
        const href = el.dataset.href;
        if (href) location.hash = href;
      });
    });
  }

  // Router
  function route() {
    const hash = location.hash || '#/';
    const parts = hash.slice(2).split('/');
    const view = parts[0] || '';
    const param = parts[1] || '';

    // Auth gate: proactively check token expiry BEFORE rendering any
    // view. Without this, the UI renders stale logged-in chrome (sidebar
    // user-info, sign-out button) from the decodable-but-expired JWT
    // payload, while the next API call 401s — producing an inconsistent
    // "half logged-in" state. Clearing the token and redirecting here
    // ensures a clean transition to the login screen.
    if (view !== 'login' && auth.getToken() && auth.isTokenExpired()) {
      auth.clearToken();
      location.hash = '#/login';
      return;
    }

    // Auth gate: if the user has a JWT and it says they must change
    // their password, force them to the change-password screen first.
    // No other view is reachable until the flag is cleared.
    if (auth.mustChangePassword() && view !== 'change-password' && view !== 'login') {
      location.hash = '#/change-password';
      return;
    }

    // Auth-mode chrome: hide the sidebar on full-screen auth pages
    // (login, change-password) so the user isn't presented with nav
    // links they can't meaningfully use. CSS uses body.auth-mode to
    // collapse the sidebar and reset the content margin.
    const authMode = view === 'login' || view === 'change-password';
    document.body.classList.toggle('auth-mode', authMode);

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

    // Sidebar user-info card: show the current user's name + role and
    // the org they belong to, so a logged-in operator can tell at a
    // glance which tenant they're looking at. Values come from the JWT
    // claims set by the server (signUserToken embeds org_name best-
    // effort; it may be briefly stale after an admin renames the org).
    // Hidden entirely on auth-mode pages (login, change-password).
    const userInfo = $('#user-info');
    if (userInfo) {
      const c = auth.getClaims();
      if (c && !authMode) {
        const orgEl = $('#user-info-org');
        const nameEl = $('#user-info-name');
        const roleEl = $('#user-info-role');
        if (orgEl) orgEl.textContent = c.org_name || '(no organization)';
        if (nameEl) nameEl.textContent = c.name || '';
        if (roleEl) {
          // Map machine-readable role values to friendly labels. Keep
          // the switch exhaustive so adding a new role doesn't
          // silently display the raw string.
          let label = c.role || '';
          if (c.role === 'org_admin') label = 'Admin';
          else if (c.role === 'org_user') label = 'User';
          else if (c.role === 'platform_admin') label = 'Platform Admin';
          roleEl.textContent = label;
        }
        userInfo.style.display = '';
      } else {
        userInfo.style.display = 'none';
      }
    }

    switch(view) {
      case 'login': renderLogin(); break;
      case 'change-password': renderChangePassword(); break;
      case 'users': param ? renderUserDetail(param) : renderUsers(); break;
      case 'inventory': renderInventory(); break;
      case 'certificates': renderCertificates(); break;
      case 'priority': renderPriority(); break;
      case 'systems': if (window.renderSystems) window.renderSystems(); break;
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
      scheduleTokenRefresh();
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
    if (!auth.getToken() || auth.isTokenExpired()) {
      auth.clearToken();
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
      // If the server fails to return a token, we refuse to keep the
      // stale mcp=true JWT (which would re-trigger the forced-change
      // gate on every page load). Clear local state and force re-login.
      if (data && data.token) {
        auth.setToken(data.token);
        scheduleTokenRefresh();
        location.hash = '#/';
      } else {
        auth.clearToken();
        location.hash = '#/login';
      }
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
    // Defense-in-depth: the router's mcp gate should have redirected
    // already, but re-check here in case renderUsers is invoked via a
    // direct function call that bypasses route().
    if (auth.mustChangePassword()) {
      location.hash = '#/change-password';
      return;
    }
    if (!auth.isAdmin()) {
      content.innerHTML = '<div class="error">Access denied — org admin role required.</div>';
      return;
    }
    content.innerHTML = '<div class="loading">Loading users...</div>';
    try {
      const users = await api('/users');
      let html = `<div class="view-header">
        <h2>Users</h2>
        <button class="btn btn-primary" id="btnShowCreateUser">Add user</button>
      </div>`;
      html += `<div id="userFormContainer"></div>`;
      html += `<table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Created</th><th></th></tr></thead>
        <tbody>`;
      if (users && users.length) {
        for (const u of users) {
          // Delete button uses data-* attrs + a delegated click handler.
          // This avoids inline onclick="...('${u.email}')" which is a
          // stored-XSS vector when email contains a single quote.
          html += `<tr>
            <td>${escapeHtml(u.name)}</td>
            <td>${escapeHtml(u.email)}</td>
            <td><span class="badge">${escapeHtml(u.role)}</span></td>
            <td>${formatDate(u.createdAt)}</td>
            <td><button class="btn btn-outline btn-sm js-delete-user" data-user-id="${escapeHtml(u.id)}" data-user-email="${escapeHtml(u.email)}">Delete</button></td>
          </tr>`;
        }
      } else {
        html += `<tr><td colspan="5" class="muted">No users yet.</td></tr>`;
      }
      html += `</tbody></table>`;
      content.innerHTML = html;

      // Wire up event handlers after innerHTML is set.
      const addBtn = $('#btnShowCreateUser');
      if (addBtn) addBtn.addEventListener('click', showCreateUserForm);
      $$('.js-delete-user').forEach(btn => {
        btn.addEventListener('click', (ev) => {
          const id = ev.currentTarget.dataset.userId;
          const email = ev.currentTarget.dataset.userEmail;
          deleteUser(id, email);
        });
      });
    } catch (e) {
      content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
  }

  function showCreateUserForm() {
    $('#userFormContainer').innerHTML = `
      <div class="auth-card">
        <h3>Add user</h3>
        <form id="createUserForm">
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
          <button type="button" class="btn btn-outline" id="btnCancelCreateUser">Cancel</button>
          <div id="newUserError" class="form-error"></div>
        </form>
      </div>
    `;
    $('#createUserForm').addEventListener('submit', createUserHandler);
    $('#btnCancelCreateUser').addEventListener('click', () => {
      $('#userFormContainer').innerHTML = '';
    });
  }

  async function createUserHandler(e) {
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
  }

  async function deleteUser(id, email) {
    if (!confirm('Delete user ' + email + '? This cannot be undone.')) return;
    try {
      await api('/users/' + encodeURIComponent(id), {method: 'DELETE'});
      renderUsers();
    } catch (err) {
      alert('Delete failed: ' + err.message);
    }
  }

  // renderUserDetail is a stub for #/users/{id} — currently routes back
  // to the list. Reserved for a future per-user edit screen.
  function renderUserDetail(_id) {
    if (auth.mustChangePassword()) {
      location.hash = '#/change-password';
      return;
    }
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
      // Parallel fetch — both idempotent GETs. Executive summary
      // failure degrades gracefully: the existing Overview still
      // renders from /aggregate.
      const [agg, exec] = await Promise.all([
        api('/aggregate'),
        api('/executive').catch(function(e) {
          console.warn('executive summary unavailable:', e);
          return null;
        }),
      ]);

      let html = '<h2>Organization Overview</h2>';
      if (exec) {
        html += renderExecSummaryBar(exec);
      }
      html += renderStatCards(agg, exec ? exec.machineHealth : null);
      html += renderChartsRow();
      if (exec && exec.topBlockers && exec.topBlockers.length > 0) {
        html += renderTopBlockers(exec.topBlockers);
      }
      html += renderMachinesTable(agg.machines);

      content.innerHTML = html;
      wireClickableRows();
      renderDonutChart(agg);
      renderBarChart(agg);
      renderBackfillBanner(content);
    } catch (e) {
      content.innerHTML = '<div class="error">Failed to load: ' + escapeHtml(e.message) + '</div>';
    }
  }

  // renderExecSummaryBar renders the Analytics Phase 2 executive
  // summary block: readiness headline, trend chip, two policy chips,
  // projection text with status-specific color.
  function renderExecSummaryBar(exec) {
    const r = exec.readiness;
    const t = exec.trend;
    const p = exec.projection;

    // Trend chip class based on direction.
    let trendChipCls = 'exec-chip--trend-stable';
    let trendLabel = 'stable';
    if (t.direction === 'improving') {
      trendChipCls = 'exec-chip--trend-improving';
      trendLabel = '↗ improving · +' + t.deltaPercent.toFixed(1) + '%';
    } else if (t.direction === 'declining') {
      trendChipCls = 'exec-chip--trend-declining';
      trendLabel = '↘ declining · ' + t.deltaPercent.toFixed(1) + '%';
    } else if (t.direction === 'insufficient-history') {
      trendChipCls = 'exec-chip--trend-stable';
      trendLabel = 'insufficient history';
    } else {
      trendLabel = '→ stable';
    }

    // Two policy chips.
    const policyChips = (exec.policyVerdicts || []).map(function(v) {
      let cls = 'exec-chip--pass';
      if (v.verdict === 'WARN') cls = 'exec-chip--warn';
      else if (v.verdict === 'FAIL') cls = 'exec-chip--fail';
      return '<span class="exec-chip ' + cls + '">' +
        escapeHtml(v.policyLabel) + ': ' + escapeHtml(v.verdict) +
        (v.violationCount > 0 ? ' · ' + v.violationCount + ' violations' : '') +
        '</span>';
    }).join('');

    // Projection text with status class.
    const projectionCls = 'exec-projection exec-projection--' + escapeHtml(p.status);

    return '<div class="exec-summary-bar">' +
      '<div class="exec-readiness">' +
        '<div class="exec-label">Readiness</div>' +
        '<div class="exec-value">' + r.percent.toFixed(1) + '%</div>' +
      '</div>' +
      '<span class="exec-chip ' + trendChipCls + '">' + escapeHtml(trendLabel) + '</span>' +
      policyChips +
      '<div class="' + projectionCls + '" title="Target ' + escapeHtml(String(p.targetPercent)) +
      '% by ' + escapeHtml(String(p.deadlineYear)) + ' (org settings)">' +
        escapeHtml(p.explanationText) +
      '</div>' +
    '</div>';
  }

  // renderStatCards renders the 6-card stat row. Machines card
  // optionally shows the red/yellow/green tier breakdown when
  // machineHealth is non-null.
  function renderStatCards(agg, machineHealth) {
    let machinesCard;
    if (machineHealth) {
      machinesCard = '<div class="card info" data-testid="machines-card">' +
        '<div class="value">' + escapeHtml(agg.machineCount) + '</div>' +
        '<div class="label">Machines' +
          '<div class="machine-tiers">' +
            '<span class="tier tier-red">' + machineHealth.red + '</span>' +
            '<span class="tier tier-yellow">' + machineHealth.yellow + '</span>' +
            '<span class="tier tier-green">' + machineHealth.green + '</span>' +
          '</div>' +
        '</div>' +
      '</div>';
    } else {
      machinesCard = '<div class="card info" data-testid="machines-card">' +
        '<div class="value">' + escapeHtml(agg.machineCount) + '</div>' +
        '<div class="label">Machines</div>' +
      '</div>';
    }

    return '<div class="card-grid">' +
      machinesCard +
      '<div class="card info"><div class="value">' + escapeHtml(agg.totalFindings) + '</div><div class="label">Total Findings</div></div>' +
      '<div class="card safe"><div class="value">' + escapeHtml(agg.safe) + '</div><div class="label">Safe</div></div>' +
      '<div class="card transitional"><div class="value">' + escapeHtml(agg.transitional) + '</div><div class="label">Transitional</div></div>' +
      '<div class="card deprecated"><div class="value">' + escapeHtml(agg.deprecated) + '</div><div class="label">Deprecated</div></div>' +
      '<div class="card unsafe"><div class="value">' + escapeHtml(agg.unsafe) + '</div><div class="label">Unsafe</div></div>' +
    '</div>';
  }

  // renderChartsRow emits the donut + bar chart canvases. Actual
  // chart instances are attached by renderDonutChart / renderBarChart.
  function renderChartsRow() {
    return '<div class="charts-row">' +
      '<div class="chart-box"><h3>PQC Status Distribution</h3><canvas id="donutChart" width="300" height="300"></canvas></div>' +
      '<div class="chart-box"><h3>Machines by Risk</h3><canvas id="barChart" width="400" height="300"></canvas></div>' +
    '</div>';
  }

  // renderTopBlockers renders the Analytics Phase 2 top-5 blockers
  // strip with a "See all priorities" link to the Phase 1 priority view.
  function renderTopBlockers(blockers) {
    const chips = blockers.map(function(b) {
      const algo = b.algorithm + (b.keySize ? '-' + b.keySize : '');
      return '<span class="blocker-chip" title="' +
        'Priority ' + b.priority + ' · ' + escapeHtml(b.module) + ' on ' + escapeHtml(b.hostname) + '">' +
        '<span class="blocker-score">' + b.priority + '</span>' +
        '<span class="blocker-algo">' + escapeHtml(algo) + '</span>' +
      '</span>';
    }).join('');

    return '<div class="top-blockers-strip">' +
      '<div class="top-blockers-label">Top priority blockers</div>' +
      '<div class="top-blockers-list">' + chips + '</div>' +
      '<a href="#/priority" class="top-blockers-more">See all priorities →</a>' +
    '</div>';
  }

  // renderMachinesTable renders the existing machines table.
  function renderMachinesTable(machines) {
    if (!machines || machines.length === 0) return '';
    let html = '<h3>Machines</h3><table>' +
      '<thead><tr><th>Hostname</th><th>Last Scan</th><th>Findings</th><th>Safe</th><th>Trans.</th><th>Depr.</th><th>Unsafe</th></tr></thead>' +
      '<tbody>';
    for (const m of machines) {
      html += '<tr class="clickable-row" data-href="#/machines/' + escapeHtml(m.hostname) + '">' +
        '<td>' + escapeHtml(m.hostname) + '</td><td>' + formatDate(m.timestamp) + '</td>' +
        '<td>' + escapeHtml(m.totalFindings) + '</td>' +
        '<td>' + escapeHtml(m.safe) + '</td><td>' + escapeHtml(m.transitional) + '</td>' +
        '<td>' + escapeHtml(m.deprecated) + '</td><td>' + escapeHtml(m.unsafe) + '</td></tr>';
    }
    html += '</tbody></table>';
    return html;
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
        html += `<tr class="clickable-row" data-href="#/machines/${escapeHtml(m.hostname)}">
          <td>${escapeHtml(m.hostname)}</td><td>${escapeHtml(m.id)}</td>
          <td>${formatDate(m.timestamp)}</td><td>${escapeHtml(m.totalFindings)}</td></tr>`;
      }
      html += `</tbody></table>`;
      content.innerHTML = html;
      wireClickableRows();
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
        <button class="btn btn-outline js-back-machines">Back</button></div>`;

      html += `<table>
        <thead><tr><th>Scan ID</th><th>Time</th><th>Profile</th><th>Findings</th><th>Safe</th><th>Trans.</th><th>Depr.</th><th>Unsafe</th></tr></thead>
        <tbody>`;
      for (const s of scans) {
        html += `<tr class="clickable-row" data-href="#/scans/${escapeHtml(s.id)}">
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
      wireClickableRows();
      const backBtn = document.querySelector('.js-back-machines');
      if (backBtn) backBtn.addEventListener('click', () => { location.hash = '#/machines'; });

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
        html += `<tr class="clickable-row" data-href="#/scans/${escapeHtml(s.id)}">
          <td>${escapeHtml(s.id.slice(0,8))}...</td><td>${escapeHtml(s.hostname)}</td>
          <td>${formatDate(s.timestamp)}</td><td>${escapeHtml(s.profile)}</td>
          <td>${escapeHtml(s.totalFindings)}</td><td>${escapeHtml(s.safe)}</td><td>${escapeHtml(s.unsafe)}</td></tr>`;
      }
      html += `</tbody></table>`;
      content.innerHTML = html;
      wireClickableRows();
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

      // Report download buttons. Click handlers are wired after
      // innerHTML is set via data-format attributes — see
      // wireDownloadButtons below. A plain <a href> would not work
      // because the report endpoint requires the JWT Authorization
      // header, which only fetch() calls attach. Tier-blocked
      // formats (e.g. sarif on pro tier) surface as a 403 alert
      // when clicked, rather than being pre-filtered client-side.
      html += `<div class="download-row">
        <span class="download-label">Download report:</span>
        <button class="btn btn-sm js-download-report" data-format="json">JSON</button>
        <button class="btn btn-sm js-download-report" data-format="html">HTML</button>
        <button class="btn btn-sm js-download-report" data-format="xlsx">NACSA: Arahan 9</button>
        <button class="btn btn-sm js-download-report" data-format="cdx">CycloneDX</button>
        <button class="btn btn-sm js-download-report" data-format="sarif">SARIF</button>
      </div>`;

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
      wireDownloadButtons(id);
    } catch(e) {
      content.innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
    }
  }

  // wireDownloadButtons attaches click handlers to every
  // `.js-download-report` button on the scan detail page. The
  // scanId is captured once per render so the handlers don't
  // have to re-read the hash. Buttons read their format from a
  // data-format attribute — no dynamic HTML interpolation, so
  // no XSS surface.
  function wireDownloadButtons(scanId) {
    $$('.js-download-report').forEach(btn => {
      btn.addEventListener('click', async () => {
        const fmt = btn.dataset.format;
        if (!fmt) return;
        // Disable the button while the download is in flight so
        // impatient clickers don't fire multiple requests.
        const originalText = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Downloading…';
        try {
          await downloadReport(scanId, fmt);
        } catch (err) {
          alert('Download failed: ' + err.message);
        } finally {
          btn.disabled = false;
          btn.textContent = originalText;
        }
      });
    });
  }

  // downloadReport fetches /api/v1/reports/{id}/{format} with the
  // stored JWT and streams the response body into a browser
  // download. A plain <a href> link would not work because the
  // report endpoint requires the Authorization header — only
  // fetch() attaches it.
  //
  // On a 200 response the body is converted to a Blob, an object
  // URL is created, a synthetic <a download> element is clicked to
  // trigger the browser's save dialog, and the object URL is
  // revoked to free the blob.
  //
  // On a non-200 response the error message (if JSON-shaped) is
  // surfaced to the caller for display in an alert — the most
  // common case is a 403 when the user's tier doesn't allow the
  // requested format (e.g., pro tier asking for sarif).
  async function downloadReport(scanId, format) {
    const token = auth.getToken();
    const headers = {};
    if (token) headers['Authorization'] = 'Bearer ' + token;

    const resp = await fetch('/api/v1/reports/' + encodeURIComponent(scanId) + '/' + encodeURIComponent(format), {
      method: 'GET',
      headers,
    });

    if (resp.status === 401) {
      // Token expired / revoked — punt to login the same way the
      // api() helper does on 401s.
      auth.clearToken();
      location.hash = '#/login';
      throw new Error('authentication required');
    }
    if (!resp.ok) {
      // Try to extract a JSON error message; fall back to a
      // generic status-code message if the server returned
      // binary content or empty body.
      let msg = `Server returned ${resp.status}`;
      try {
        const err = await resp.json();
        if (err.error) msg = err.error;
      } catch (_) {}
      throw new Error(msg);
    }

    // Convert the body to a Blob. The Content-Type from the
    // server is preserved so the browser's Save As dialog opens
    // the right default app (Excel for .xlsx, a browser for
    // .html, etc.) — note the blob constructor's `type` option
    // is authoritative for download-attribute semantics, not
    // the response's Content-Type header alone.
    const blob = await resp.blob();

    // Prefer the Content-Disposition filename from the server,
    // falling back to a sensible default. Content-Disposition
    // parsing is minimal — we only care about the filename
    // attribute in the quoted form the handler produces.
    let filename = defaultDownloadFilename(scanId, format);
    const cd = resp.headers.get('Content-Disposition') || '';
    const match = cd.match(/filename="([^"]+)"/);
    if (match && match[1]) filename = match[1];

    const objectURL = URL.createObjectURL(blob);
    try {
      const a = document.createElement('a');
      a.href = objectURL;
      a.download = filename;
      // Firefox requires the anchor to be in the DOM before a
      // programmatic click fires the download; Chromium is more
      // lenient but this works everywhere.
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    } finally {
      // Always revoke the object URL to release the blob's
      // memory, even if the click threw.
      URL.revokeObjectURL(objectURL);
    }
  }

  // defaultDownloadFilename returns the filename the browser will
  // save the report under when the server didn't supply a
  // Content-Disposition header (which should never happen, but
  // the fallback keeps downloads usable even if a reverse proxy
  // strips the header).
  function defaultDownloadFilename(scanId, format) {
    const shortID = scanId.slice(0, 8);
    switch (format) {
      case 'json':  return `triton-report-${shortID}.json`;
      case 'html':  return `triton-report-${shortID}.html`;
      case 'xlsx':  return `Triton_PQC_Report-${shortID}.xlsx`;
      case 'cdx':   return `triton-report-${shortID}.cdx.json`;
      case 'sarif': return `triton-report-${shortID}.sarif`;
      default:      return `triton-report-${shortID}.${format}`;
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

  // ─── Analytics Phase 3 — category filters ──────────────────────────

  var filterOptionsCache = null;
  var inventoryFilters = {hostname: '', pqcStatus: ''};
  var certFilters = {hostname: '', algorithm: ''};
  var priorityFilters = {hostname: '', pqcStatus: ''};

  async function getFilterOptions() {
    if (filterOptionsCache) return filterOptionsCache;
    try {
      filterOptionsCache = await api('/filters');
    } catch (e) {
      filterOptionsCache = {hostnames: [], algorithms: [], pqcStatuses: []};
    }
    return filterOptionsCache;
  }

  function renderFilterBar(filters, activeValues, onChange) {
    var html = '<div class="filter-bar">';
    for (var i = 0; i < filters.length; i++) {
      var f = filters[i];
      html += '<label class="filter-label">' + escapeHtml(f.label) + ': ';
      html += '<select data-filter-key="' + f.key + '">';
      html += '<option value="">All</option>';
      for (var j = 0; j < f.options.length; j++) {
        var opt = f.options[j];
        var selected = activeValues[f.key] === opt ? ' selected' : '';
        html += '<option value="' + escapeHtml(opt) + '"' + selected + '>' + escapeHtml(opt) + '</option>';
      }
      html += '</select></label>';
    }
    html += '</div>';
    return html;
  }

  function wireFilterBar(container, activeValues, onChange) {
    var selects = container.querySelectorAll('.filter-bar select');
    for (var i = 0; i < selects.length; i++) {
      (function(sel) {
        sel.addEventListener('change', function() {
          activeValues[sel.dataset.filterKey] = sel.value;
          onChange();
        });
      })(selects[i]);
    }
  }

  function buildFilterQuery(params) {
    var parts = [];
    for (var key in params) {
      if (params[key]) parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
    }
    return parts.length ? '&' + parts.join('&') : '';
  }

  // ─── Analytics Phase 1 views (extended with Phase 3 filters) ──────

  async function renderInventory() {
    content.innerHTML = '<div class="loading">Loading crypto inventory...</div>';
    try {
      var opts = await getFilterOptions();
      var qp = buildFilterQuery({hostname: inventoryFilters.hostname, pqc_status: inventoryFilters.pqcStatus});
      const rows = await api('/inventory?' + qp);
      let html = '<h2>Crypto Inventory</h2>' +
        '<p class="subtitle">Aggregated by algorithm and key size across all machines in your organization (latest scan per host).</p>' +
        renderFilterBar([
          {label: 'Hostname', key: 'hostname', options: opts.hostnames || []},
          {label: 'PQC Status', key: 'pqcStatus', options: opts.pqcStatuses || []}
        ], inventoryFilters, renderInventory);
      if (!rows || rows.length === 0) {
        html += '<div class="empty-state">No findings yet — run a scan to see your crypto inventory.</div>';
      } else {
        html += '<table class="analytics-table"><thead><tr>' +
          '<th>Algorithm</th><th>Size</th><th>Status</th>' +
          '<th class="num">Instances</th><th class="num">Machines</th><th class="num">Max Priority</th>' +
          '</tr></thead><tbody>';
        for (const row of rows) {
          html += '<tr>' +
            '<td>' + escapeHtml(row.algorithm) + '</td>' +
            '<td>' + (row.keySize > 0 ? escapeHtml(row.keySize) : '—') + '</td>' +
            '<td>' + badge(row.pqcStatus) + '</td>' +
            '<td class="num">' + escapeHtml(row.instances) + '</td>' +
            '<td class="num">' + escapeHtml(row.machines) + '</td>' +
            '<td class="num">' + (row.maxPriority > 0 ? escapeHtml(row.maxPriority) : '—') + '</td>' +
            '</tr>';
        }
        html += '</tbody></table>';
      }
      content.innerHTML = html;
      wireFilterBar(content, inventoryFilters, renderInventory);
      renderBackfillBanner(content);
    } catch (e) {
      content.innerHTML = '<div class="error">Failed to load inventory: ' + escapeHtml(e.message) + '</div>';
    }
  }

  // certFilterDays is the currently-selected window for the
  // Expiring Certificates view. Persisted in module state so filter
  // chip clicks don't require a full re-render of the chrome.
  let certFilterDays = 90;

  async function renderCertificates() {
    content.innerHTML = '<div class="loading">Loading certificates...</div>';
    try {
      var opts = await getFilterOptions();
      const param = certFilterDays === 'all' ? 'all' : String(certFilterDays);
      var cfp = buildFilterQuery({hostname: certFilters.hostname, algorithm: certFilters.algorithm});
      const rows = await api('/certificates/expiring?within=' + param + cfp);

      // Summary counts computed from the rows we just fetched. Note
      // these reflect only what the current window returned — to see
      // a wider view, click the "All" chip which broadens the query.
      let expired = 0, urgent = 0, warning = 0;
      for (const r of rows) {
        if (r.daysRemaining < 0) expired++;
        else if (r.daysRemaining <= 30) urgent++;
        else if (r.daysRemaining <= 90) warning++;
      }

      let html = '<h2>Expiring Certificates</h2>' +
        '<p class="subtitle">Latest-scan certificates sorted by soonest expiry. Already-expired certs are always included regardless of the filter.</p>' +
        renderFilterBar([
          {label: 'Hostname', key: 'hostname', options: opts.hostnames || []},
          {label: 'Algorithm', key: 'algorithm', options: opts.algorithms || []}
        ], certFilters, renderCertificates) +
        '<div class="summary-chips">' +
          '<div class="summary-chip critical"><strong>' + expired + '</strong> expired</div>' +
          '<div class="summary-chip urgent"><strong>' + urgent + '</strong> within 30 days</div>' +
          '<div class="summary-chip warning"><strong>' + warning + '</strong> within 90 days</div>' +
          '<div class="summary-chip"><strong>' + rows.length + '</strong> shown</div>' +
        '</div>' +
        '<div class="form-row" style="gap:8px;margin-bottom:12px">' +
          ['30', '90', '180', 'all'].map(function(d) {
            const active = String(certFilterDays) === d;
            const label = d === 'all' ? 'All' : d + ' days';
            return '<button class="btn" data-window="' + d + '" style="opacity:' + (active ? '1' : '0.6') + '">' + label + '</button>';
          }).join('') +
        '</div>';

      if (rows.length === 0) {
        html += '<div class="empty-state">No certificates match this filter.</div>';
      } else {
        html += '<table class="analytics-table"><thead><tr>' +
          '<th>Subject</th><th>Host</th><th>Algorithm</th>' +
          '<th class="num">Expires in</th><th>Status</th>' +
          '</tr></thead><tbody>';
        for (const row of rows) {
          const days = row.daysRemaining;
          const daysText = days < 0 ? 'expired ' + (-days) + 'd ago' : days + ' days';
          const algo = row.algorithm + (row.keySize ? '-' + row.keySize : '');
          html += '<tr>' +
            '<td>' + escapeHtml(row.subject) + '</td>' +
            '<td>' + escapeHtml(row.hostname) + '</td>' +
            '<td>' + escapeHtml(algo) + '</td>' +
            '<td class="num">' + escapeHtml(daysText) + '</td>' +
            '<td>' + badge(row.status) + '</td>' +
            '</tr>';
        }
        html += '</tbody></table>';
      }

      content.innerHTML = html;
      wireFilterBar(content, certFilters, renderCertificates);
      renderBackfillBanner(content);

      // Wire up filter chip buttons. Each click updates the module-
      // level certFilterDays and re-renders. The selected chip stays
      // highlighted via opacity = 1.
      $$('button[data-window]').forEach(function(btn) {
        btn.addEventListener('click', function() {
          const v = btn.dataset.window;
          certFilterDays = v === 'all' ? 'all' : parseInt(v, 10);
          renderCertificates();
        });
      });
    } catch (e) {
      content.innerHTML = '<div class="error">Failed to load certificates: ' + escapeHtml(e.message) + '</div>';
    }
  }

  async function renderPriority() {
    content.innerHTML = '<div class="loading">Loading priority findings...</div>';
    try {
      var opts = await getFilterOptions();
      var pfp = buildFilterQuery({hostname: priorityFilters.hostname, pqc_status: priorityFilters.pqcStatus});
      const rows = await api('/priority?limit=20' + pfp);

      // Bucket counts for the summary cards.
      let critical = 0, high = 0, medium = 0;
      for (const r of rows) {
        if (r.priority >= 80) critical++;
        else if (r.priority >= 60) high++;
        else if (r.priority >= 40) medium++;
      }

      let html = '<h2>Migration Priority</h2>' +
        '<p class="subtitle">Top findings to fix first, ranked by migration priority score (latest scan per host, top 20).</p>' +
        renderFilterBar([
          {label: 'Hostname', key: 'hostname', options: opts.hostnames || []},
          {label: 'PQC Status', key: 'pqcStatus', options: opts.pqcStatuses || []}
        ], priorityFilters, renderPriority) +
        '<div class="card-grid">' +
          '<div class="card unsafe"><div class="value">' + critical + '</div><div class="label">Critical (≥80)</div></div>' +
          '<div class="card deprecated"><div class="value">' + high + '</div><div class="label">High (60–79)</div></div>' +
          '<div class="card transitional"><div class="value">' + medium + '</div><div class="label">Medium (40–59)</div></div>' +
          '<div class="card info"><div class="value">' + rows.length + '</div><div class="label">Shown</div></div>' +
        '</div>';

      if (rows.length === 0) {
        html += '<div class="empty-state">No priority findings yet — run a scan.</div>';
      } else {
        html += '<table class="analytics-table"><thead><tr>' +
          '<th class="num">Score</th><th>Algorithm</th><th>Module</th>' +
          '<th>Host</th><th>Location</th><th>Status</th>' +
          '</tr></thead><tbody>';
        for (const row of rows) {
          const algo = row.algorithm + (row.keySize ? '-' + row.keySize : '');
          const loc = row.filePath || '—';
          html += '<tr>' +
            '<td class="num">' + escapeHtml(row.priority) + '</td>' +
            '<td>' + escapeHtml(algo) + '</td>' +
            '<td>' + escapeHtml(row.module) + '</td>' +
            '<td>' + escapeHtml(row.hostname) + '</td>' +
            '<td><code>' + escapeHtml(loc) + '</code></td>' +
            '<td>' + badge(row.pqcStatus) + '</td>' +
            '</tr>';
        }
        html += '</tbody></table>';
      }

      content.innerHTML = html;
      wireFilterBar(content, priorityFilters, renderPriority);
      renderBackfillBanner(content);
    } catch (e) {
      content.innerHTML = '<div class="error">Failed to load priority findings: ' + escapeHtml(e.message) + '</div>';
    }
  }

  // ─── Session lifecycle ───────────────────────────────────────────────
  // checkSessionExpiry is the single source of truth for client-side
  // expiry detection. It checks the JWT exp claim and, if expired,
  // clears the token and bounces to login. Returns true if expired.
  function checkSessionExpiry() {
    if (auth.getToken() && auth.isTokenExpired()) {
      auth.clearToken();
      location.hash = '#/login';
      return true;
    }
    return false;
  }

  // Proactive token refresh — calls POST /auth/refresh ~5 minutes
  // before the JWT expires. On success, stores the new token and
  // re-schedules. On failure, the 401 handler or expiry check will
  // bounce the user to login at expiry time.
  let refreshTimer = null;
  function scheduleTokenRefresh() {
    if (refreshTimer) { clearTimeout(refreshTimer); refreshTimer = null; }
    const claims = auth.getClaims();
    if (!claims || !claims.exp) return;
    const msUntilExpiry = (claims.exp * 1000) - Date.now();
    // Refresh 5 minutes before expiry; if less than 30s remain, don't
    // bother — the expiry check will handle it.
    const refreshIn = msUntilExpiry - (5 * 60 * 1000);
    if (refreshIn < 30000) return;
    refreshTimer = setTimeout(async function() {
      try {
        const data = await api('/auth/refresh', { method: 'POST' });
        if (data && data.token) {
          auth.setToken(data.token);
          scheduleTokenRefresh();
        }
      } catch (_) {
        // Refresh failed — let the expiry check or next api() 401 handle it.
      }
    }, refreshIn);
  }

  // Tab-return detection: when the user switches back to this tab after
  // leaving it overnight, re-validate the session immediately rather
  // than waiting for the next API call or the 60s interval.
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      if (!checkSessionExpiry()) {
        // Token still valid — reschedule refresh in case the timer
        // drifted while the tab was backgrounded (browsers throttle
        // setTimeout in hidden tabs).
        scheduleTokenRefresh();
      }
    }
  });

  // Periodic expiry check — catches silent expiry even when the tab
  // stays focused. 60s is well below the 24h JWT TTL so the user
  // never sits on a stale session for more than a minute.
  setInterval(function() {
    checkSessionExpiry();
  }, 60000);

  // Init
  // The renderOverview() initial call will hit the API. In single-tenant
  // mode (Guard provides tenant context), it returns 200 and the UI
  // renders normally — no login needed. In multi-tenant mode without
  // a stored token, the API returns 401, the api() helper redirects
  // to #/login, and the user signs in.
  window.addEventListener('hashchange', route);
  route();
  // Kick off token refresh scheduling if we already have a valid token
  // (e.g., page reload with a stored JWT).
  scheduleTokenRefresh();
})();
