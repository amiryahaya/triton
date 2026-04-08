// Triton License Server Admin UI
(function() {
  'use strict';

  // Use sessionStorage instead of localStorage to limit credential exposure.
  // Key is cleared when the browser tab/window is closed.
  let adminKey = sessionStorage.getItem('triton_admin_key') || '';
  const page = document.getElementById('page');

  // UUID format validation for IDs from hash/API.
  var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  // Session inactivity timeout: clear credentials after 30 minutes of inactivity.
  var lastActivity = Date.now();
  document.addEventListener('click', function() { lastActivity = Date.now(); });
  document.addEventListener('keydown', function() { lastActivity = Date.now(); });
  setInterval(function() {
    if (adminKey && (Date.now() - lastActivity > 30 * 60 * 1000)) {
      sessionStorage.removeItem('triton_admin_key');
      adminKey = '';
      showAuthPrompt();
    }
  }, 60 * 1000);

  function api(method, path, body) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    if (adminKey) opts.headers['X-Triton-Admin-Key'] = adminKey;
    if (body) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(r => {
      if (r.status === 401 || r.status === 403) {
        sessionStorage.removeItem('triton_admin_key');
        adminKey = '';
        showAuthPrompt();
        throw new Error('Unauthorized');
      }
      if (!r.ok) {
        return r.json().catch(() => ({})).then(data => {
          throw new Error(data.error || 'Request failed');
        });
      }
      return r.json().catch(() => { throw new Error('Invalid server response'); });
    });
  }

  function showAuthPrompt() {
    page.innerHTML = `
      <div id="auth-prompt">
        <img src="logo.png" alt="Triton" class="auth-logo">
        <h2>Triton License Server</h2>
        <p>Enter your admin API key to continue.</p>
        <div class="auth-form">
          <label for="key-input" class="sr-only">Admin API Key</label>
          <input type="password" id="key-input" placeholder="Admin API Key">
          <button class="btn btn-primary" id="key-submit">Authenticate</button>
        </div>
      </div>`;
    document.getElementById('key-submit').onclick = function() {
      var val = document.getElementById('key-input').value;
      if (!val.trim()) return;
      adminKey = val;
      sessionStorage.setItem('triton_admin_key', adminKey);
      route();
    };
    document.getElementById('key-input').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') document.getElementById('key-submit').click();
    });
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s || '';
    return div.innerHTML;
  }

  // Coerce to safe integer string for HTML interpolation.
  function safeInt(v) { return String(parseInt(v, 10) || 0); }

  function formatDate(d) {
    if (!d) return '-';
    return new Date(d).toLocaleString();
  }

  function tierBadge(tier) {
    return '<span class="tier-badge tier-' + escapeHtml(tier) + '">' + escapeHtml(tier) + '</span>';
  }

  function statusBadge(lic) {
    if (lic.revoked) return '<span class="badge badge-revoked">Revoked</span>';
    if (lic.isExpired) return '<span class="badge badge-expired">Expired</span>';
    return '<span class="badge badge-active">Active</span>';
  }

  // --- Stat card icons ---
  var statIcons = {
    orgs: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 17V4a1 1 0 011-1h5a1 1 0 011 1v13"/><path d="M9 17V8a1 1 0 011-1h5a1 1 0 011 1v9"/><line x1="2" y1="17" x2="16" y2="17"/></svg>',
    totalLic: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="5" width="14" height="10" rx="2"/><circle cx="7.5" cy="10" r="2"/><path d="M12 8h2m-2 2h2m-2 2h2"/></svg>',
    activeLic: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 2l1.5 3h3.5l-2.8 2 1 3.5L9 8.5 5.8 10.5l1-3.5L4 5h3.5z"/><path d="M4 14h12m-10 3h8"/></svg>',
    seats: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="7" cy="6" r="2.5"/><circle cx="13" cy="6" r="2.5"/><path d="M2 16c0-3 2.5-5 5-5s5 2 5 5"/><path d="M11 11c2.5 0 5 2 5 5"/></svg>',
    revoked: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="10" cy="10" r="7"/><line x1="5" y1="5" x2="15" y2="15"/></svg>',
    expired: '<svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="10" cy="10" r="7"/><polyline points="10,6 10,10 13,12"/></svg>'
  };

  // --- Pages ---

  async function dashboardPage() {
    page.innerHTML = '<h2>Dashboard</h2><p class="text-muted">Loading...</p>';
    try {
      const stats = await api('GET', '/api/v1/admin/stats');
      page.innerHTML = '<h2>Dashboard</h2>' +
        '<div class="stat-cards">' +
          '<div class="stat-card"><div class="stat-icon">' + statIcons.orgs + '</div><div class="value">' + safeInt(stats.totalOrgs) + '</div><div class="label">Organizations</div></div>' +
          '<div class="stat-card"><div class="stat-icon">' + statIcons.totalLic + '</div><div class="value">' + safeInt(stats.totalLicenses) + '</div><div class="label">Total Licenses</div></div>' +
          '<div class="stat-card"><div class="stat-icon">' + statIcons.activeLic + '</div><div class="value">' + safeInt(stats.activeLicenses) + '</div><div class="label">Active Licenses</div></div>' +
          '<div class="stat-card"><div class="stat-icon">' + statIcons.seats + '</div><div class="value">' + safeInt(stats.activeSeats) + '</div><div class="label">Active Seats</div></div>' +
          '<div class="stat-card"><div class="stat-icon">' + statIcons.revoked + '</div><div class="value">' + safeInt(stats.revokedLicenses) + '</div><div class="label">Revoked</div></div>' +
          '<div class="stat-card"><div class="stat-icon">' + statIcons.expired + '</div><div class="value">' + safeInt(stats.expiredLicenses) + '</div><div class="label">Expired</div></div>' +
        '</div>';
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<h2>Dashboard</h2><p class="text-danger">Error loading stats</p>'; }
  }

  async function orgsPage() {
    page.innerHTML = '<h2>Organizations</h2><p class="text-muted">Loading...</p>';
    try {
      const orgs = await api('GET', '/api/v1/admin/orgs');
      let html = '<h2>Organizations</h2>' +
        '<div class="actions"><button class="btn btn-primary" id="create-org-btn">Create Organization</button></div>' +
        '<table><thead><tr><th>Name</th><th>Contact</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
      for (const o of orgs) {
        html += '<tr>' +
          '<td>' + escapeHtml(o.name) + '</td>' +
          '<td>' + escapeHtml(o.contact) + '</td>' +
          '<td>' + formatDate(o.createdAt) + '</td>' +
          '<td><button class="btn btn-danger btn-sm" data-delete-org="' + escapeHtml(o.id) + '">Delete</button></td>' +
        '</tr>';
      }
      html += '</tbody></table>';
      page.innerHTML = html;
      document.getElementById('create-org-btn').onclick = showCreateOrgModal;
      page.querySelectorAll('[data-delete-org]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm('Delete this organization?')) return;
          try {
            await api('DELETE', '/api/v1/admin/orgs/' + encodeURIComponent(btn.dataset.deleteOrg));
            orgsPage();
          } catch(e) { alert('Operation failed. Please try again.'); }
        };
      });
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<h2>Organizations</h2><p class="text-danger">Error loading organizations</p>'; }
  }

  function showCreateOrgModal() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = '<div class="modal">' +
      '<h3>Create Organization</h3>' +
      '<div class="form-group"><label for="org-name">Name</label><input id="org-name" maxlength="255"></div>' +
      '<div class="form-group"><label for="org-contact">Contact</label><input id="org-contact" maxlength="255"></div>' +
      '<div class="form-group"><label for="org-notes">Notes</label><textarea id="org-notes" rows="3" maxlength="1000"></textarea></div>' +
      '<hr style="margin:16px 0;border:none;border-top:1px solid var(--border)">' +
      '<p class="text-muted" style="margin:0 0 12px 0;font-size:13px">' +
        '<strong>Optional:</strong> Provision an org admin on the report server. ' +
        'When set, the report server will create the admin user with a temporary ' +
        'password. The temp password will be shown once and (if Resend is configured) ' +
        'emailed to the admin.</p>' +
      '<div class="form-group"><label for="org-admin-email">Admin email</label>' +
        '<input id="org-admin-email" type="email" maxlength="255" placeholder="alice@example.com"></div>' +
      '<div class="form-group"><label for="org-admin-name">Admin name</label>' +
        '<input id="org-admin-name" type="text" maxlength="255" placeholder="Alice Admin"></div>' +
      '<div class="modal-actions">' +
        '<button class="btn" id="modal-cancel">Cancel</button>' +
        '<button class="btn btn-primary" id="modal-create">Create</button>' +
      '</div>' +
    '</div>';
    document.body.appendChild(overlay);
    overlay.querySelector('#modal-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#modal-create').onclick = async function() {
      var name = document.getElementById('org-name').value.trim();
      if (!name) { alert('Name is required'); return; }
      var adminEmail = document.getElementById('org-admin-email').value.trim();
      var adminName = document.getElementById('org-admin-name').value.trim();
      // Both-or-neither — server enforces this too, but catch early.
      if ((adminEmail && !adminName) || (!adminEmail && adminName)) {
        alert('Admin email and name must be supplied together (or both left blank).');
        return;
      }
      this.disabled = true;
      try {
        var body = {
          name: name,
          contact: document.getElementById('org-contact').value,
          notes: document.getElementById('org-notes').value
        };
        if (adminEmail) {
          body.admin_email = adminEmail;
          body.admin_name = adminName;
        }
        var resp = await api('POST', '/api/v1/admin/orgs', body);
        overlay.remove();
        // If the server provisioned an admin, show the temp password once.
        if (resp && resp.admin) {
          showProvisioningResult(resp);
        }
        orgsPage();
      } catch(e) { this.disabled = false; alert('Operation failed: ' + e.message); }
    };
  }

  // showProvisioningResult displays the temp password from a successful
  // org creation with admin provisioning. The password is shown ONCE and
  // is the only way to deliver it manually if email delivery failed.
  function showProvisioningResult(resp) {
    var emailDelivered = resp.admin && resp.admin.email_delivered;
    var emailNote = emailDelivered
      ? '<p class="text-success">An invite email has been sent to ' + escapeHtml(resp.admin.email) + '.</p>'
      : '<p class="text-warning"><strong>Email delivery failed</strong> (or no mailer configured). ' +
        'You must deliver the temporary password to the admin out of band — copy it now, it will not be shown again.</p>';
    var overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = '<div class="modal">' +
      '<h3>Organization Created</h3>' +
      '<p>Org <strong>' + escapeHtml(resp.org.name) + '</strong> created with admin user.</p>' +
      emailNote +
      '<div class="form-group"><label>Admin email</label>' +
        '<input type="text" readonly value="' + escapeHtml(resp.admin.email) + '" onclick="this.select()"></div>' +
      '<div class="form-group"><label>Temporary password (one time)</label>' +
        '<input type="text" readonly value="' + escapeHtml(resp.admin.temp_password) + '" onclick="this.select()" style="font-family:monospace"></div>' +
      '<div class="modal-actions"><button class="btn btn-primary" id="prov-close">Close</button></div>' +
    '</div>';
    document.body.appendChild(overlay);
    overlay.querySelector('#prov-close').onclick = () => overlay.remove();
  }

  async function licensesPage() {
    page.innerHTML = '<h2>Licenses</h2><p class="text-muted">Loading...</p>';
    try {
      const lics = await api('GET', '/api/v1/admin/licenses');
      let html = '<h2>Licenses</h2>' +
        '<div class="actions"><button class="btn btn-primary" id="create-lic-btn">Create License</button></div>' +
        '<table><thead><tr><th>ID</th><th>Org</th><th>Tier</th><th>Seats</th><th>Used</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead><tbody>';
      for (const l of lics) {
        html += '<tr>' +
          '<td><a href="#/licenses/' + escapeHtml(l.id) + '">' + escapeHtml(l.id.substring(0,8)) + '...</a></td>' +
          '<td>' + escapeHtml(l.orgName) + '</td>' +
          '<td>' + tierBadge(l.tier) + '</td>' +
          '<td>' + safeInt(l.seats) + '</td>' +
          '<td>' + safeInt(l.seatsUsed) + '</td>' +
          '<td>' + formatDate(l.expiresAt) + '</td>' +
          '<td>' + statusBadge(l) + '</td>' +
          '<td>' + (!l.revoked ? '<button class="btn btn-danger btn-sm" data-revoke="' + escapeHtml(l.id) + '">Revoke</button>' : '') + '</td>' +
        '</tr>';
      }
      html += '</tbody></table>';
      page.innerHTML = html;
      document.getElementById('create-lic-btn').onclick = showCreateLicenseModal;
      page.querySelectorAll('[data-revoke]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm('Revoke this license? All activations will be deactivated.')) return;
          try {
            await api('POST', '/api/v1/admin/licenses/' + encodeURIComponent(btn.dataset.revoke) + '/revoke', {});
            licensesPage();
          } catch(e) { alert('Operation failed. Please try again.'); }
        };
      });
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<h2>Licenses</h2><p class="text-danger">Error loading licenses</p>'; }
  }

  async function showCreateLicenseModal() {
    let orgs;
    try { orgs = await api('GET', '/api/v1/admin/orgs'); } catch(e) { return; }
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    let orgOpts = orgs.map(o => '<option value="' + escapeHtml(o.id) + '">' + escapeHtml(o.name) + '</option>').join('');
    overlay.innerHTML = '<div class="modal">' +
      '<h3>Create License</h3>' +
      '<div class="form-group"><label for="lic-org">Organization</label><select id="lic-org">' + orgOpts + '</select></div>' +
      '<div class="form-group"><label for="lic-tier">Tier</label><select id="lic-tier"><option>pro</option><option>enterprise</option><option>free</option></select></div>' +
      '<div class="form-group"><label for="lic-seats">Seats</label><input type="number" id="lic-seats" value="5" min="1"></div>' +
      '<div class="form-group"><label for="lic-days">Days</label><input type="number" id="lic-days" value="365" min="1"></div>' +
      '<div class="form-group"><label for="lic-notes">Notes</label><textarea id="lic-notes" rows="2" maxlength="1000"></textarea></div>' +
      '<div class="modal-actions">' +
        '<button class="btn" id="modal-cancel">Cancel</button>' +
        '<button class="btn btn-primary" id="modal-create">Create</button>' +
      '</div>' +
    '</div>';
    document.body.appendChild(overlay);
    overlay.querySelector('#modal-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#modal-create').onclick = async function() {
      var seats = parseInt(document.getElementById('lic-seats').value, 10);
      var days = parseInt(document.getElementById('lic-days').value, 10);
      if (isNaN(seats) || seats < 1) { alert('Seats must be a positive number'); return; }
      if (isNaN(days) || days < 1) { alert('Days must be a positive number'); return; }
      this.disabled = true;
      try {
        await api('POST', '/api/v1/admin/licenses', {
          orgID: document.getElementById('lic-org').value,
          tier: document.getElementById('lic-tier').value,
          seats: seats,
          days: days,
          notes: document.getElementById('lic-notes').value
        });
        overlay.remove();
        licensesPage();
      } catch(e) { this.disabled = false; alert('Operation failed. Please try again.'); }
    };
  }

  async function licenseDetailPage(id) {
    // Validate ID format to prevent path traversal in API calls.
    if (!UUID_RE.test(id)) {
      page.innerHTML = '<h2>License Detail</h2><p class="text-danger">Invalid license ID format</p>';
      return;
    }
    page.innerHTML = '<h2>License Detail</h2><p class="text-muted">Loading...</p>';
    try {
      const data = await api('GET', '/api/v1/admin/licenses/' + encodeURIComponent(id));
      let html = '<h2>License Detail</h2>' +
        '<table>' +
          '<tr><th>ID</th><td class="mono">' + escapeHtml(data.id) + '</td></tr>' +
          '<tr><th>Organization</th><td>' + escapeHtml(data.orgName) + '</td></tr>' +
          '<tr><th>Tier</th><td>' + tierBadge(data.tier) + '</td></tr>' +
          '<tr><th>Seats</th><td>' + safeInt(data.seatsUsed) + ' / ' + safeInt(data.seats) + '</td></tr>' +
          '<tr><th>Issued</th><td>' + formatDate(data.issuedAt) + '</td></tr>' +
          '<tr><th>Expires</th><td>' + formatDate(data.expiresAt) + '</td></tr>' +
          '<tr><th>Status</th><td>' + statusBadge(data) + '</td></tr>' +
        '</table>' +
        '<h3>Activations</h3>' +
        '<table><thead><tr><th>Machine</th><th>Hostname</th><th>OS/Arch</th><th>Last Seen</th><th>Active</th></tr></thead><tbody>';
      for (const a of (data.activations || [])) {
        html += '<tr>' +
          '<td class="mono">' + escapeHtml(a.machineID.substring(0,16)) + '...</td>' +
          '<td>' + escapeHtml(a.hostname) + '</td>' +
          '<td>' + escapeHtml(a.os) + '/' + escapeHtml(a.arch) + '</td>' +
          '<td>' + formatDate(a.lastSeenAt) + '</td>' +
          '<td>' + (a.active ? '<span class="badge badge-active">Yes</span>' : '<span class="badge badge-revoked">No</span>') + '</td>' +
        '</tr>';
      }
      html += '</tbody></table>';
      page.innerHTML = html;
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<h2>License Detail</h2><p class="text-danger">Error loading license</p>'; }
  }

  async function activationsPage() {
    page.innerHTML = '<h2>Activations</h2><p class="text-muted">Loading...</p>';
    try {
      const acts = await api('GET', '/api/v1/admin/activations');
      let html = '<h2>Activations</h2>' +
        '<table><thead><tr><th>Machine</th><th>Hostname</th><th>OS/Arch</th><th>License</th><th>Last Seen</th><th>Active</th></tr></thead><tbody>';
      for (const a of acts) {
        html += '<tr>' +
          '<td class="mono">' + escapeHtml(a.machineID.substring(0,16)) + '...</td>' +
          '<td>' + escapeHtml(a.hostname) + '</td>' +
          '<td>' + escapeHtml(a.os) + '/' + escapeHtml(a.arch) + '</td>' +
          '<td><a href="#/licenses/' + escapeHtml(a.licenseID) + '">' + escapeHtml(a.licenseID.substring(0,8)) + '...</a></td>' +
          '<td>' + formatDate(a.lastSeenAt) + '</td>' +
          '<td>' + (a.active ? '<span class="badge badge-active">Yes</span>' : '<span class="badge badge-revoked">No</span>') + '</td>' +
        '</tr>';
      }
      html += '</tbody></table>';
      page.innerHTML = html;
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<h2>Activations</h2><p class="text-danger">Error loading activations</p>'; }
  }

  async function auditPage() {
    page.innerHTML = '<h2>Audit Log</h2><p class="text-muted">Loading...</p>';
    try {
      const entries = await api('GET', '/api/v1/admin/audit?limit=100');
      let html = '<h2>Audit Log</h2>' +
        '<table><thead><tr><th>Time</th><th>Event</th><th>License</th><th>Machine</th><th>IP</th></tr></thead><tbody>';
      for (const e of entries) {
        html += '<tr>' +
          '<td>' + formatDate(e.timestamp) + '</td>' +
          '<td><span class="mono accent">' + escapeHtml(e.eventType) + '</span></td>' +
          '<td>' + (e.licenseID ? '<span class="mono">' + escapeHtml(e.licenseID.substring(0,8)) + '...</span>' : '-') + '</td>' +
          '<td>' + (e.machineID ? '<span class="mono">' + escapeHtml(e.machineID.substring(0,16)) + '...</span>' : '-') + '</td>' +
          '<td>' + escapeHtml(e.ipAddress) + '</td>' +
        '</tr>';
      }
      html += '</tbody></table>';
      page.innerHTML = html;
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<h2>Audit Log</h2><p class="text-danger">Error loading audit log</p>'; }
  }

  // --- Binaries ---

  async function binariesPage() {
    page.innerHTML = '<h2>Binaries</h2><p class="text-muted">Loading...</p>';
    try {
      const binaries = await api('GET', '/api/v1/admin/binaries');
      let html = '<h2>Binaries</h2>' +
        '<div class="actions"><button class="btn btn-primary" id="upload-bin-btn">Upload Binary</button></div>' +
        '<table><thead><tr><th>Version</th><th>OS</th><th>Arch</th><th>Size</th><th>SHA3-256</th><th>Uploaded</th><th>Actions</th></tr></thead><tbody>';
      for (const b of binaries) {
        var sizeMB = (Number(b.size) / (1024 * 1024)).toFixed(1) + ' MB';
        html += '<tr>' +
          '<td><span class="mono accent">' + escapeHtml(b.version) + '</span></td>' +
          '<td>' + escapeHtml(b.os) + '</td>' +
          '<td>' + escapeHtml(b.arch) + '</td>' +
          '<td>' + escapeHtml(sizeMB) + '</td>' +
          '<td title="' + escapeHtml(b.sha3) + '"><span class="mono">' + escapeHtml(b.sha3.substring(0,12)) + '...</span></td>' +
          '<td>' + formatDate(b.uploadedAt) + '</td>' +
          '<td><button class="btn btn-danger btn-sm" data-delete-bin="' + escapeHtml(b.version) + '/' + escapeHtml(b.os) + '/' + escapeHtml(b.arch) + '">Delete</button></td>' +
        '</tr>';
      }
      if (binaries.length === 0) {
        html += '<tr><td colspan="7">No binaries uploaded yet</td></tr>';
      }
      html += '</tbody></table>';
      page.innerHTML = html;
      document.getElementById('upload-bin-btn').onclick = showUploadBinaryModal;
      page.querySelectorAll('[data-delete-bin]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm('Delete this binary?')) return;
          try {
            // Split and re-encode each path segment to prevent path traversal.
            var parts = btn.dataset.deleteBin.split('/');
            var safePath = parts.map(encodeURIComponent).join('/');
            await api('DELETE', '/api/v1/admin/binaries/' + safePath);
            binariesPage();
          } catch(e) { alert('Operation failed. Please try again.'); }
        };
      });
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<h2>Binaries</h2><p class="text-danger">Error loading binaries</p>'; }
  }

  function showUploadBinaryModal() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = '<div class="modal">' +
      '<h3>Upload Binary</h3>' +
      '<div class="form-group"><label for="bin-version">Version</label><input id="bin-version" placeholder="e.g. 1.0.0" maxlength="50"></div>' +
      '<div class="form-group"><label for="bin-os">OS</label><select id="bin-os"><option>linux</option><option>darwin</option><option>windows</option></select></div>' +
      '<div class="form-group"><label for="bin-arch">Architecture</label><select id="bin-arch"><option>amd64</option><option>arm64</option></select></div>' +
      '<div class="form-group"><label for="bin-file">Binary File</label><input type="file" id="bin-file" class="file-input"></div>' +
      '<div id="upload-progress" class="upload-progress-hidden"></div>' +
      '<div class="modal-actions">' +
        '<button class="btn" id="modal-cancel">Cancel</button>' +
        '<button class="btn btn-primary" id="modal-upload">Upload</button>' +
      '</div>' +
    '</div>';
    document.body.appendChild(overlay);
    overlay.querySelector('#modal-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#modal-upload').onclick = async function() {
      const version = document.getElementById('bin-version').value.trim();
      const os = document.getElementById('bin-os').value;
      const arch = document.getElementById('bin-arch').value;
      const fileInput = document.getElementById('bin-file');
      if (!version || !fileInput.files.length) { alert('Version and file are required'); return; }
      this.disabled = true;
      const progress = document.getElementById('upload-progress');
      progress.className = 'upload-progress';
      progress.textContent = 'Uploading...';
      try {
        const fd = new FormData();
        fd.append('version', version);
        fd.append('os', os);
        fd.append('arch', arch);
        fd.append('file', fileInput.files[0]);
        const resp = await fetch('/api/v1/admin/binaries', {
          method: 'POST',
          headers: { 'X-Triton-Admin-Key': adminKey },
          body: fd
        });
        if (resp.status === 401 || resp.status === 403) {
          sessionStorage.removeItem('triton_admin_key');
          adminKey = '';
          showAuthPrompt();
          return;
        }
        if (!resp.ok) throw new Error('Upload failed');
        overlay.remove();
        binariesPage();
      } catch(e) {
        progress.textContent = 'Upload failed. Please check the file and try again.';
        progress.className = 'upload-progress upload-error';
      }
    };
  }

  // --- Superadmins page (Phase 3.2) ---

  async function superadminsPage() {
    page.innerHTML = '<h2>Superadmins</h2><p class="text-muted">Loading...</p>';
    try {
      const admins = await api('GET', '/api/v1/admin/superadmins');
      let html = '<h2>Superadmins</h2>' +
        '<p class="text-muted">Platform administrators who can sign in to this license server. ' +
        'These are distinct from organization users (which live in the report server).</p>' +
        '<div class="actions"><button class="btn btn-primary" id="create-sa-btn">Add Superadmin</button></div>' +
        '<table><thead><tr><th>Name</th><th>Email</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
      if (admins && admins.length) {
        for (const u of admins) {
          html += '<tr>' +
            '<td>' + escapeHtml(u.name) + '</td>' +
            '<td>' + escapeHtml(u.email) + '</td>' +
            '<td>' + formatDate(u.createdAt) + '</td>' +
            '<td><button class="btn btn-danger btn-sm" data-delete-sa="' + escapeHtml(u.id) + '" data-email="' + escapeHtml(u.email) + '">Delete</button></td>' +
          '</tr>';
        }
      } else {
        html += '<tr><td colspan="4" class="text-muted">No superadmins yet.</td></tr>';
      }
      html += '</tbody></table>';
      page.innerHTML = html;
      document.getElementById('create-sa-btn').onclick = showCreateSuperadminModal;
      page.querySelectorAll('[data-delete-sa]').forEach(btn => {
        btn.onclick = async () => {
          const email = btn.dataset.email;
          if (!confirm('Delete superadmin ' + email + '? This cannot be undone.')) return;
          try {
            await api('DELETE', '/api/v1/admin/superadmins/' + encodeURIComponent(btn.dataset.deleteSa));
            superadminsPage();
          } catch (e) {
            alert('Delete failed: ' + e.message);
          }
        };
      });
    } catch (e) {
      if (e.message !== 'Unauthorized') page.innerHTML = '<h2>Superadmins</h2><p class="text-danger">Error: ' + escapeHtml(e.message) + '</p>';
    }
  }

  function showCreateSuperadminModal() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = '<div class="modal">' +
      '<h3>Add Superadmin</h3>' +
      '<p class="text-muted" style="margin:0 0 12px 0;font-size:13px">' +
        'Superadmins can sign into this license server with email + password. ' +
        'Min 12-character password required.</p>' +
      '<div class="form-group"><label for="sa-email">Email</label><input id="sa-email" type="email" maxlength="255"></div>' +
      '<div class="form-group"><label for="sa-name">Name</label><input id="sa-name" type="text" maxlength="255"></div>' +
      '<div class="form-group"><label for="sa-password">Password</label><input id="sa-password" type="password" minlength="12"></div>' +
      '<div class="modal-actions">' +
        '<button class="btn" id="modal-cancel">Cancel</button>' +
        '<button class="btn btn-primary" id="modal-create">Create</button>' +
      '</div>' +
    '</div>';
    document.body.appendChild(overlay);
    overlay.querySelector('#modal-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#modal-create').onclick = async function () {
      var email = document.getElementById('sa-email').value.trim();
      var name = document.getElementById('sa-name').value.trim();
      var password = document.getElementById('sa-password').value;
      if (!email || !name || !password) { alert('All fields required'); return; }
      if (password.length < 12) { alert('Password must be at least 12 characters'); return; }
      this.disabled = true;
      try {
        await api('POST', '/api/v1/admin/superadmins', { email: email, name: name, password: password });
        overlay.remove();
        superadminsPage();
      } catch (e) {
        this.disabled = false;
        alert('Create failed: ' + e.message);
      }
    };
  }

  // --- Routing ---

  function route() {
    if (!adminKey) { showAuthPrompt(); return; }
    const hash = location.hash || '#/';
    document.querySelectorAll('.nav-link').forEach(el => {
      el.classList.toggle('active', el.getAttribute('href') === hash || (hash.startsWith(el.getAttribute('href')) && el.getAttribute('href') !== '#/'));
    });
    if (hash === '#/' || hash === '') dashboardPage();
    else if (hash === '#/orgs') orgsPage();
    else if (hash === '#/licenses') licensesPage();
    else if (hash.startsWith('#/licenses/')) licenseDetailPage(hash.split('/')[2]);
    else if (hash === '#/activations') activationsPage();
    else if (hash === '#/audit') auditPage();
    else if (hash === '#/binaries') binariesPage();
    else if (hash === '#/superadmins') superadminsPage();
    else page.innerHTML = '<h2>Page Not Found</h2>';
  }

  window.addEventListener('hashchange', route);
  route();
})();
