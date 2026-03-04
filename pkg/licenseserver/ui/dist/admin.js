// Triton License Server Admin UI
(function() {
  'use strict';

  let adminKey = localStorage.getItem('triton_admin_key') || '';
  const page = document.getElementById('page');

  function api(method, path, body) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    if (adminKey) opts.headers['X-Triton-Admin-Key'] = adminKey;
    if (body) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(r => {
      if (r.status === 401 || r.status === 403) {
        localStorage.removeItem('triton_admin_key');
        adminKey = '';
        showAuthPrompt();
        throw new Error('Unauthorized');
      }
      return r.json();
    });
  }

  function showAuthPrompt() {
    page.innerHTML = `
      <div id="auth-prompt">
        <h2>Admin Authentication</h2>
        <p>Enter your admin API key to continue.</p>
        <input type="password" id="key-input" placeholder="Admin API Key">
        <br><button class="btn btn-primary" id="key-submit">Login</button>
      </div>`;
    document.getElementById('key-submit').onclick = function() {
      adminKey = document.getElementById('key-input').value;
      localStorage.setItem('triton_admin_key', adminKey);
      route();
    };
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s || '';
    return div.innerHTML;
  }

  function formatDate(d) {
    if (!d) return '-';
    return new Date(d).toLocaleString();
  }

  function tierBadge(tier) {
    const colors = { free: '#6c757d', pro: '#0d6efd', enterprise: '#198754' };
    return `<span style="color:${colors[tier]||'#333'};font-weight:600">${escapeHtml(tier)}</span>`;
  }

  function statusBadge(lic) {
    if (lic.revoked) return '<span class="badge badge-revoked">Revoked</span>';
    if (lic.isExpired) return '<span class="badge badge-expired">Expired</span>';
    return '<span class="badge badge-active">Active</span>';
  }

  // --- Pages ---

  async function dashboardPage() {
    page.innerHTML = '<h2>Dashboard</h2><p>Loading...</p>';
    try {
      const stats = await api('GET', '/api/v1/admin/stats');
      page.innerHTML = `
        <h2>Dashboard</h2>
        <div class="stat-cards">
          <div class="stat-card"><div class="value">${stats.totalOrgs}</div><div class="label">Organizations</div></div>
          <div class="stat-card"><div class="value">${stats.totalLicenses}</div><div class="label">Total Licenses</div></div>
          <div class="stat-card"><div class="value">${stats.activeLicenses}</div><div class="label">Active Licenses</div></div>
          <div class="stat-card"><div class="value">${stats.activeSeats}</div><div class="label">Active Seats</div></div>
          <div class="stat-card"><div class="value">${stats.revokedLicenses}</div><div class="label">Revoked</div></div>
          <div class="stat-card"><div class="value">${stats.expiredLicenses}</div><div class="label">Expired</div></div>
        </div>`;
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<p>Error loading stats</p>'; }
  }

  async function orgsPage() {
    page.innerHTML = '<h2>Organizations</h2><p>Loading...</p>';
    try {
      const orgs = await api('GET', '/api/v1/admin/orgs');
      let html = `<h2>Organizations</h2>
        <div class="actions"><button class="btn btn-primary" id="create-org-btn">Create Organization</button></div>
        <table><thead><tr><th>Name</th><th>Contact</th><th>Created</th><th>Actions</th></tr></thead><tbody>`;
      for (const o of orgs) {
        html += `<tr>
          <td>${escapeHtml(o.name)}</td>
          <td>${escapeHtml(o.contact)}</td>
          <td>${formatDate(o.createdAt)}</td>
          <td><button class="btn btn-danger btn-sm" data-delete-org="${o.id}">Delete</button></td>
        </tr>`;
      }
      html += '</tbody></table>';
      page.innerHTML = html;
      document.getElementById('create-org-btn').onclick = showCreateOrgModal;
      page.querySelectorAll('[data-delete-org]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm('Delete this organization?')) return;
          try {
            await api('DELETE', '/api/v1/admin/orgs/' + btn.dataset.deleteOrg);
            orgsPage();
          } catch(e) { alert('Failed: ' + e.message); }
        };
      });
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<p>Error loading organizations</p>'; }
  }

  function showCreateOrgModal() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal">
      <h3>Create Organization</h3>
      <div class="form-group"><label>Name</label><input id="org-name"></div>
      <div class="form-group"><label>Contact</label><input id="org-contact"></div>
      <div class="form-group"><label>Notes</label><textarea id="org-notes" rows="3"></textarea></div>
      <div class="modal-actions">
        <button class="btn" id="modal-cancel">Cancel</button>
        <button class="btn btn-primary" id="modal-create">Create</button>
      </div>
    </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('#modal-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#modal-create').onclick = async () => {
      try {
        await api('POST', '/api/v1/admin/orgs', {
          name: document.getElementById('org-name').value,
          contact: document.getElementById('org-contact').value,
          notes: document.getElementById('org-notes').value
        });
        overlay.remove();
        orgsPage();
      } catch(e) { alert('Failed: ' + e.message); }
    };
  }

  async function licensesPage() {
    page.innerHTML = '<h2>Licenses</h2><p>Loading...</p>';
    try {
      const lics = await api('GET', '/api/v1/admin/licenses');
      let html = `<h2>Licenses</h2>
        <div class="actions"><button class="btn btn-primary" id="create-lic-btn">Create License</button></div>
        <table><thead><tr><th>ID</th><th>Org</th><th>Tier</th><th>Seats</th><th>Used</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead><tbody>`;
      for (const l of lics) {
        html += `<tr>
          <td><a href="#/licenses/${l.id}">${escapeHtml(l.id.substring(0,8))}...</a></td>
          <td>${escapeHtml(l.orgName)}</td>
          <td>${tierBadge(l.tier)}</td>
          <td>${l.seats}</td>
          <td>${l.seatsUsed}</td>
          <td>${formatDate(l.expiresAt)}</td>
          <td>${statusBadge(l)}</td>
          <td>${!l.revoked ? '<button class="btn btn-danger btn-sm" data-revoke="'+l.id+'">Revoke</button>' : ''}</td>
        </tr>`;
      }
      html += '</tbody></table>';
      page.innerHTML = html;
      document.getElementById('create-lic-btn').onclick = showCreateLicenseModal;
      page.querySelectorAll('[data-revoke]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm('Revoke this license? All activations will be deactivated.')) return;
          try {
            await api('POST', '/api/v1/admin/licenses/' + btn.dataset.revoke + '/revoke', {});
            licensesPage();
          } catch(e) { alert('Failed: ' + e.message); }
        };
      });
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<p>Error loading licenses</p>'; }
  }

  async function showCreateLicenseModal() {
    let orgs;
    try { orgs = await api('GET', '/api/v1/admin/orgs'); } catch(e) { return; }
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    let orgOpts = orgs.map(o => `<option value="${o.id}">${escapeHtml(o.name)}</option>`).join('');
    overlay.innerHTML = `<div class="modal">
      <h3>Create License</h3>
      <div class="form-group"><label>Organization</label><select id="lic-org">${orgOpts}</select></div>
      <div class="form-group"><label>Tier</label><select id="lic-tier"><option>pro</option><option>enterprise</option><option>free</option></select></div>
      <div class="form-group"><label>Seats</label><input type="number" id="lic-seats" value="5" min="1"></div>
      <div class="form-group"><label>Days</label><input type="number" id="lic-days" value="365" min="1"></div>
      <div class="form-group"><label>Notes</label><textarea id="lic-notes" rows="2"></textarea></div>
      <div class="modal-actions">
        <button class="btn" id="modal-cancel">Cancel</button>
        <button class="btn btn-primary" id="modal-create">Create</button>
      </div>
    </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('#modal-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#modal-create').onclick = async () => {
      try {
        await api('POST', '/api/v1/admin/licenses', {
          orgID: document.getElementById('lic-org').value,
          tier: document.getElementById('lic-tier').value,
          seats: parseInt(document.getElementById('lic-seats').value),
          days: parseInt(document.getElementById('lic-days').value),
          notes: document.getElementById('lic-notes').value
        });
        overlay.remove();
        licensesPage();
      } catch(e) { alert('Failed: ' + e.message); }
    };
  }

  async function licenseDetailPage(id) {
    page.innerHTML = '<h2>License Detail</h2><p>Loading...</p>';
    try {
      const data = await api('GET', '/api/v1/admin/licenses/' + id);
      let html = `<h2>License Detail</h2>
        <table>
          <tr><th>ID</th><td>${escapeHtml(data.id)}</td></tr>
          <tr><th>Organization</th><td>${escapeHtml(data.orgName)}</td></tr>
          <tr><th>Tier</th><td>${tierBadge(data.tier)}</td></tr>
          <tr><th>Seats</th><td>${data.seatsUsed} / ${data.seats}</td></tr>
          <tr><th>Issued</th><td>${formatDate(data.issuedAt)}</td></tr>
          <tr><th>Expires</th><td>${formatDate(data.expiresAt)}</td></tr>
          <tr><th>Status</th><td>${statusBadge(data)}</td></tr>
        </table>
        <h3 style="margin:20px 0 10px">Activations</h3>
        <table><thead><tr><th>Machine</th><th>Hostname</th><th>OS/Arch</th><th>Last Seen</th><th>Active</th></tr></thead><tbody>`;
      for (const a of (data.activations || [])) {
        html += `<tr>
          <td>${escapeHtml(a.machineID.substring(0,16))}...</td>
          <td>${escapeHtml(a.hostname)}</td>
          <td>${escapeHtml(a.os)}/${escapeHtml(a.arch)}</td>
          <td>${formatDate(a.lastSeenAt)}</td>
          <td>${a.active ? '<span class="badge badge-active">Yes</span>' : '<span class="badge badge-revoked">No</span>'}</td>
        </tr>`;
      }
      html += '</tbody></table>';
      page.innerHTML = html;
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<p>Error loading license</p>'; }
  }

  async function activationsPage() {
    page.innerHTML = '<h2>Activations</h2><p>Loading...</p>';
    try {
      const acts = await api('GET', '/api/v1/admin/activations');
      let html = `<h2>Activations</h2>
        <table><thead><tr><th>Machine</th><th>Hostname</th><th>OS/Arch</th><th>License</th><th>Last Seen</th><th>Active</th></tr></thead><tbody>`;
      for (const a of acts) {
        html += `<tr>
          <td>${escapeHtml(a.machineID.substring(0,16))}...</td>
          <td>${escapeHtml(a.hostname)}</td>
          <td>${escapeHtml(a.os)}/${escapeHtml(a.arch)}</td>
          <td><a href="#/licenses/${a.licenseID}">${escapeHtml(a.licenseID.substring(0,8))}...</a></td>
          <td>${formatDate(a.lastSeenAt)}</td>
          <td>${a.active ? '<span class="badge badge-active">Yes</span>' : '<span class="badge badge-revoked">No</span>'}</td>
        </tr>`;
      }
      html += '</tbody></table>';
      page.innerHTML = html;
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<p>Error loading activations</p>'; }
  }

  async function auditPage() {
    page.innerHTML = '<h2>Audit Log</h2><p>Loading...</p>';
    try {
      const entries = await api('GET', '/api/v1/admin/audit?limit=100');
      let html = `<h2>Audit Log</h2>
        <table><thead><tr><th>Time</th><th>Event</th><th>License</th><th>Machine</th><th>IP</th></tr></thead><tbody>`;
      for (const e of entries) {
        html += `<tr>
          <td>${formatDate(e.timestamp)}</td>
          <td>${escapeHtml(e.eventType)}</td>
          <td>${e.licenseID ? escapeHtml(e.licenseID.substring(0,8))+'...' : '-'}</td>
          <td>${e.machineID ? escapeHtml(e.machineID.substring(0,16))+'...' : '-'}</td>
          <td>${escapeHtml(e.ipAddress)}</td>
        </tr>`;
      }
      html += '</tbody></table>';
      page.innerHTML = html;
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<p>Error loading audit log</p>'; }
  }

  // --- Binaries ---

  async function binariesPage() {
    page.innerHTML = '<h2>Binaries</h2><p>Loading...</p>';
    try {
      const binaries = await api('GET', '/api/v1/admin/binaries');
      let html = `<h2>Binaries</h2>
        <div class="actions"><button class="btn btn-primary" id="upload-bin-btn">Upload Binary</button></div>
        <table><thead><tr><th>Version</th><th>OS</th><th>Arch</th><th>Size</th><th>SHA-256</th><th>Uploaded</th><th>Actions</th></tr></thead><tbody>`;
      for (const b of binaries) {
        const sizeMB = (b.size / (1024 * 1024)).toFixed(1) + ' MB';
        html += `<tr>
          <td>${escapeHtml(b.version)}</td>
          <td>${escapeHtml(b.os)}</td>
          <td>${escapeHtml(b.arch)}</td>
          <td>${sizeMB}</td>
          <td title="${escapeHtml(b.sha256)}">${escapeHtml(b.sha256.substring(0,12))}...</td>
          <td>${formatDate(b.uploadedAt)}</td>
          <td><button class="btn btn-danger btn-sm" data-delete-bin="${escapeHtml(b.version)}/${escapeHtml(b.os)}/${escapeHtml(b.arch)}">Delete</button></td>
        </tr>`;
      }
      if (binaries.length === 0) {
        html += '<tr><td colspan="7" style="text-align:center;color:#6c757d">No binaries uploaded</td></tr>';
      }
      html += '</tbody></table>';
      page.innerHTML = html;
      document.getElementById('upload-bin-btn').onclick = showUploadBinaryModal;
      page.querySelectorAll('[data-delete-bin]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm('Delete this binary?')) return;
          try {
            const resp = await fetch('/api/v1/admin/binaries/' + btn.dataset.deleteBin, {
              method: 'DELETE',
              headers: { 'X-Triton-Admin-Key': adminKey }
            });
            if (!resp.ok) {
              const err = await resp.json().catch(() => ({}));
              alert('Delete failed: ' + (err.error || 'Unknown error'));
              return;
            }
            binariesPage();
          } catch(e) { alert('Failed: ' + e.message); }
        };
      });
    } catch(e) { if (e.message !== 'Unauthorized') page.innerHTML = '<p>Error loading binaries</p>'; }
  }

  function showUploadBinaryModal() {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal">
      <h3>Upload Binary</h3>
      <div class="form-group"><label>Version</label><input id="bin-version" placeholder="e.g. 1.0.0"></div>
      <div class="form-group"><label>OS</label><select id="bin-os"><option>linux</option><option>darwin</option><option>windows</option></select></div>
      <div class="form-group"><label>Architecture</label><select id="bin-arch"><option>amd64</option><option>arm64</option></select></div>
      <div class="form-group"><label>Binary File</label><input type="file" id="bin-file"></div>
      <div id="upload-progress" style="display:none;margin:10px 0;color:#0d6efd"></div>
      <div class="modal-actions">
        <button class="btn" id="modal-cancel">Cancel</button>
        <button class="btn btn-primary" id="modal-upload">Upload</button>
      </div>
    </div>`;
    document.body.appendChild(overlay);
    overlay.querySelector('#modal-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#modal-upload').onclick = async () => {
      const version = document.getElementById('bin-version').value;
      const os = document.getElementById('bin-os').value;
      const arch = document.getElementById('bin-arch').value;
      const fileInput = document.getElementById('bin-file');
      if (!version || !fileInput.files.length) { alert('Version and file are required'); return; }
      const progress = document.getElementById('upload-progress');
      progress.style.display = 'block';
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
        if (!resp.ok) { const e = await resp.json(); throw new Error(e.error || 'Upload failed'); }
        overlay.remove();
        binariesPage();
      } catch(e) { progress.textContent = 'Error: ' + e.message; progress.style.color = '#dc3545'; }
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
    else page.innerHTML = '<h2>Page Not Found</h2>';
  }

  window.addEventListener('hashchange', route);
  route();
})();
